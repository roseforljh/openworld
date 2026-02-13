//! Phase 4D: Rule Provider 测试

use std::collections::HashMap;
use std::io::Write;

use openworld::config::types::{RouterConfig, RuleConfig, RuleProviderConfig};
use openworld::router::Router;

use tempfile::NamedTempFile;

/// 创建临时规则文件，返回 NamedTempFile（保持生命周期）
fn create_rule_file(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// --- 域名行为测试 ---

#[test]
fn rule_provider_domain_plain_text() {
    let file = create_rule_file("google.com\nyoutube.com\n");

    let mut providers = HashMap::new();
    providers.insert(
        "proxy-domains".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["proxy-domains".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        }],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    // 匹配后缀
    let session = make_session("www.google.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("youtube.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("sub.youtube.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // 不匹配
    let session = make_session("example.com", 443);
    assert_eq!(router.route(&session), "direct");
}

#[test]
fn rule_provider_domain_clash_yaml() {
    let file =
        create_rule_file("payload:\n  - '+.google.com'\n  - '+.twitter.com'\n  - 'facebook.com'\n");

    let mut providers = HashMap::new();
    providers.insert(
        "clash-domains".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["clash-domains".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        }],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    let session = make_session("www.google.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("t.co.twitter.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("facebook.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("example.com", 443);
    assert_eq!(router.route(&session), "direct");
}

#[test]
fn rule_provider_domain_with_prefix_syntax() {
    let file = create_rule_file(
        "domain:exact.example.com\ndomain_suffix:suffix.com\ndomain_keyword:google\n",
    );

    let mut providers = HashMap::new();
    providers.insert(
        "mixed-domain".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["mixed-domain".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        }],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    // domain: 完全匹配
    let session = make_session("exact.example.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("sub.exact.example.com", 443);
    assert_eq!(router.route(&session), "direct"); // 不匹配完全匹配

    // domain_suffix: 后缀匹配
    let session = make_session("www.suffix.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // domain_keyword: 关键字匹配
    let session = make_session("www.google.co.jp", 443);
    assert_eq!(router.route(&session), "proxy");
}

// --- IP CIDR 行为测试 ---

#[test]
fn rule_provider_ipcidr() {
    let file = create_rule_file("10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n");

    let mut providers = HashMap::new();
    providers.insert(
        "private-cidrs".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "ipcidr".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["private-cidrs".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        }],
        default: "proxy".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    let session = make_ip_session("10.1.2.3", 80);
    assert_eq!(router.route(&session), "direct");

    let session = make_ip_session("172.16.0.1", 443);
    assert_eq!(router.route(&session), "direct");

    let session = make_ip_session("192.168.1.1", 22);
    assert_eq!(router.route(&session), "direct");

    let session = make_ip_session("8.8.8.8", 53);
    assert_eq!(router.route(&session), "proxy");
}

#[test]
fn rule_provider_ipcidr_clash_yaml() {
    let file = create_rule_file("payload:\n  - '10.0.0.0/8'\n  - '172.16.0.0/12'\n");

    let mut providers = HashMap::new();
    providers.insert(
        "cn-cidrs".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "ipcidr".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["cn-cidrs".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        }],
        default: "proxy".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    let session = make_ip_session("10.0.0.1", 80);
    assert_eq!(router.route(&session), "direct");

    let session = make_ip_session("1.1.1.1", 53);
    assert_eq!(router.route(&session), "proxy");
}

// --- Classical 行为测试 ---

#[test]
fn rule_provider_classical() {
    let file = create_rule_file(
        "DOMAIN,exact.test.com\nDOMAIN-SUFFIX,google.com\nDOMAIN-KEYWORD,facebook\nIP-CIDR,10.0.0.0/8\nIP-CIDR,192.168.0.0/16,no-resolve\n",
    );

    let mut providers = HashMap::new();
    providers.insert(
        "mixed-rules".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "classical".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["mixed-rules".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        }],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    // DOMAIN 完全匹配
    let session = make_session("exact.test.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // DOMAIN-SUFFIX 后缀
    let session = make_session("www.google.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // DOMAIN-KEYWORD 关键字
    let session = make_session("www.facebook.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // IP-CIDR
    let session = make_ip_session("10.1.2.3", 80);
    assert_eq!(router.route(&session), "proxy");

    let session = make_ip_session("192.168.1.1", 22);
    assert_eq!(router.route(&session), "proxy");

    // 不匹配
    let session = make_session("example.com", 80);
    assert_eq!(router.route(&session), "direct");

    let session = make_ip_session("8.8.8.8", 53);
    assert_eq!(router.route(&session), "direct");
}

// --- 多 provider 测试 ---

#[test]
fn rule_provider_multiple_providers() {
    let domain_file = create_rule_file("google.com\nyoutube.com\n");
    let cidr_file = create_rule_file("10.0.0.0/8\n");

    let mut providers = HashMap::new();
    providers.insert(
        "proxy-domains".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: domain_file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );
    providers.insert(
        "private-cidrs".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "ipcidr".to_string(),
            path: cidr_file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![
            RuleConfig {
                rule_type: "rule-set".to_string(),
                values: vec!["private-cidrs".to_string()],
                outbound: "direct".to_string(),
                ..Default::default()
            },
            RuleConfig {
                rule_type: "rule-set".to_string(),
                values: vec!["proxy-domains".to_string()],
                outbound: "proxy".to_string(),
                ..Default::default()
            },
        ],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    let session = make_ip_session("10.1.2.3", 80);
    assert_eq!(router.route(&session), "direct");

    let session = make_session("www.google.com", 443);
    assert_eq!(router.route(&session), "proxy");

    let session = make_session("example.com", 80);
    assert_eq!(router.route(&session), "direct");
}

// --- 与普通规则混合测试 ---

#[test]
fn rule_provider_mixed_with_regular_rules() {
    let file = create_rule_file("google.com\n");

    let mut providers = HashMap::new();
    providers.insert(
        "proxy-domains".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![
            // 普通规则优先
            RuleConfig {
                rule_type: "domain-full".to_string(),
                values: vec!["override.google.com".to_string()],
                outbound: "special".to_string(),
                ..Default::default()
            },
            // rule-set 规则
            RuleConfig {
                rule_type: "rule-set".to_string(),
                values: vec!["proxy-domains".to_string()],
                outbound: "proxy".to_string(),
                ..Default::default()
            },
        ],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    // domain-full 规则优先匹配
    let session = make_session("override.google.com", 443);
    assert_eq!(router.route(&session), "special");

    // rule-set 匹配其他 google.com 子域名
    let session = make_session("www.google.com", 443);
    assert_eq!(router.route(&session), "proxy");

    // 都不匹配走默认
    let session = make_session("example.com", 80);
    assert_eq!(router.route(&session), "direct");
}

// --- 错误处理测试 ---

#[test]
fn rule_provider_missing_file_fails() {
    let mut providers = HashMap::new();
    providers.insert(
        "missing".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: "/nonexistent/path/rules.txt".to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    assert!(Router::new(&router_cfg).is_err());
}

#[test]
fn rule_provider_unknown_provider_name_fails() {
    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "rule-set".to_string(),
            values: vec!["nonexistent-provider".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        }],
        default: "direct".to_string(),
        ..Default::default()
    };

    assert!(Router::new(&router_cfg).is_err());
}

#[test]
fn rule_provider_unsupported_behavior_fails() {
    let file = create_rule_file("test\n");

    let mut providers = HashMap::new();
    providers.insert(
        "bad".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "unknown-behavior".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    assert!(Router::new(&router_cfg).is_err());
}

// --- Config 反序列化测试 ---

#[test]
fn config_rule_providers_deserialize() {
    let file = create_rule_file("example.com\n");
    let path = file.path().to_str().unwrap().replace('\\', "/");

    let yaml = format!(
        r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: proxy
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
  - tag: direct
    protocol: direct
router:
  rule-providers:
    my-domains:
      type: file
      behavior: domain
      path: "{path}"
    my-cidrs:
      type: http
      behavior: ipcidr
      path: "{path}"
      url: "https://example.com/cidrs.txt"
      interval: 3600
  rules:
    - type: rule-set
      values: ["my-domains"]
      outbound: proxy
  default: direct
"#
    );

    let config: openworld::config::types::Config = serde_yml::from_str(&yaml).unwrap();
    assert_eq!(config.router.rule_providers.len(), 2);

    let my_domains = &config.router.rule_providers["my-domains"];
    assert_eq!(my_domains.provider_type, "file");
    assert_eq!(my_domains.behavior, "domain");

    let my_cidrs = &config.router.rule_providers["my-cidrs"];
    assert_eq!(my_cidrs.provider_type, "http");
    assert_eq!(my_cidrs.behavior, "ipcidr");
    assert_eq!(
        my_cidrs.url.as_deref(),
        Some("https://example.com/cidrs.txt")
    );
    assert_eq!(my_cidrs.interval, 3600);
}

#[test]
fn config_without_rule_providers_still_works() {
    let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
"#;

    let config: openworld::config::types::Config = serde_yml::from_str(yaml).unwrap();
    assert!(config.router.rule_providers.is_empty());
    assert!(config.validate().is_ok());
}

// --- API 访问测试 ---

#[test]
fn router_providers_accessor() {
    let file = create_rule_file("test.com\n");

    let mut providers = HashMap::new();
    providers.insert(
        "test-provider".to_string(),
        RuleProviderConfig {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            path: file.path().to_str().unwrap().to_string(),
            url: None,
            interval: 86400,
            lazy: false,
        },
    );

    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        rule_providers: providers,
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();
    let loaded = router.providers();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.contains_key("test-provider"));

    let data = &loaded["test-provider"];
    assert!(data.matches_domain("test.com"));
    assert!(data.matches_domain("www.test.com"));
    assert!(!data.matches_domain("other.com"));
}

// --- 辅助函数 ---

fn make_session(domain: &str, port: u16) -> openworld::proxy::Session {
    use openworld::common::Address;
    use openworld::proxy::{Network, Session};
    Session {
        network: Network::Tcp,
        target: Address::Domain(domain.to_string(), port),
        source: Some("127.0.0.1:12345".parse().unwrap()),
        inbound_tag: "test".to_string(),
        sniff: false,
        detected_protocol: None,
    }
}

fn make_ip_session(ip: &str, port: u16) -> openworld::proxy::Session {
    use openworld::common::Address;
    use openworld::proxy::{Network, Session};
    use std::net::SocketAddr;
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
    Session {
        network: Network::Tcp,
        target: Address::Ip(addr),
        source: Some("127.0.0.1:12345".parse().unwrap()),
        inbound_tag: "test".to_string(),
        sniff: false,
        detected_protocol: None,
    }
}
