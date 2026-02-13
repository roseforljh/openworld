//! Phase 5: DNS + 路由增强测试

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use openworld::common::Address;
use openworld::config::types::{DnsConfig, DnsServerConfig, RouterConfig, RuleConfig};
use openworld::dns::resolver::{build_resolver, SystemResolver};
use openworld::dns::DnsResolver;
use openworld::proxy::{Network, Session};
use openworld::router::Router;

// ============================================================
// DNS 测试
// ============================================================

#[tokio::test]
async fn dns_system_resolver_resolves_localhost() {
    let resolver = SystemResolver;
    let addrs = resolver.resolve("localhost").await.unwrap();
    assert!(!addrs.is_empty());
    assert!(addrs.iter().any(|a| a.is_loopback()));
}

#[tokio::test]
async fn dns_build_resolver_empty_servers() {
    let config = DnsConfig {
        servers: vec![],
        cache_size: 1024,
        cache_ttl: 300,
        negative_cache_ttl: 30,
        hosts: Default::default(),
        fake_ip: None,
        mode: "split".to_string(),
        fallback: vec![],
        fallback_filter: None,
        edns_client_subnet: None,
        prefer_ip: None,
    };
    let (resolver, _pool) = build_resolver(&config).unwrap();
    // 空配置应使用系统解析器
    let addrs = resolver.resolve("localhost").await.unwrap();
    assert!(!addrs.is_empty());
}

#[tokio::test]
async fn dns_build_resolver_single_udp() {
    let config = DnsConfig {
        servers: vec![DnsServerConfig {
            address: "223.5.5.5".to_string(),
            domains: vec![],
        }],
        cache_size: 1024,
        cache_ttl: 300,
        negative_cache_ttl: 30,
        hosts: Default::default(),
        fake_ip: None,
        mode: "split".to_string(),
        fallback: vec![],
        fallback_filter: None,
        edns_client_subnet: None,
        prefer_ip: None,
    };
    // 构建应成功
    let (_resolver, _pool) = build_resolver(&config).unwrap();
}

#[tokio::test]
async fn dns_build_resolver_split() {
    let config = DnsConfig {
        servers: vec![
            DnsServerConfig {
                address: "223.5.5.5".to_string(),
                domains: vec!["cn".to_string()],
            },
            DnsServerConfig {
                address: "8.8.8.8".to_string(),
                domains: vec![],
            },
        ],
        cache_size: 1024,
        cache_ttl: 300,
        negative_cache_ttl: 30,
        hosts: Default::default(),
        fake_ip: None,
        mode: "split".to_string(),
        fallback: vec![],
        fallback_filter: None,
        edns_client_subnet: None,
        prefer_ip: None,
    };
    let (_resolver, _pool) = build_resolver(&config).unwrap();
}

#[tokio::test]
async fn dns_split_resolver_routing() {
    /// Mock 解析器
    struct MockDns(IpAddr);

    #[async_trait]
    impl DnsResolver for MockDns {
        async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<IpAddr>> {
            Ok(vec![self.0])
        }
    }

    let cn_dns = Arc::new(MockDns("1.2.3.4".parse().unwrap()));
    let default_dns = Arc::new(MockDns("8.8.8.8".parse().unwrap()));

    let split = openworld::dns::resolver::SplitResolver::new(
        vec![(vec![
            openworld::dns::resolver::DnsDomainRule::Suffix("cn".to_string()),
            openworld::dns::resolver::DnsDomainRule::Suffix("baidu.com".to_string()),
        ], cn_dns)],
        default_dns,
    );

    // cn 域名走中国 DNS
    let result = split.resolve("test.cn").await.unwrap();
    assert_eq!(result[0], "1.2.3.4".parse::<IpAddr>().unwrap());

    let result = split.resolve("www.baidu.com").await.unwrap();
    assert_eq!(result[0], "1.2.3.4".parse::<IpAddr>().unwrap());

    // 其他域名走默认
    let result = split.resolve("google.com").await.unwrap();
    assert_eq!(result[0], "8.8.8.8".parse::<IpAddr>().unwrap());
}

// ============================================================
// 路由增强测试
// ============================================================

#[test]
fn router_geoip_rule_without_db_does_not_match() {
    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "geoip".to_string(),
            values: vec!["CN".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        }],
        default: "proxy".to_string(),
        ..Default::default()
    };
    let router = Router::new(&router_cfg).unwrap();

    let session = Session {
        target: Address::Ip("1.2.3.4:80".parse().unwrap()),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    // 没有 GeoIP 数据库，规则不匹配，走默认
    assert_eq!(router.route(&session), "proxy");
}

#[test]
fn router_geosite_rule_without_db_does_not_match() {
    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "geosite".to_string(),
            values: vec!["cn".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        }],
        default: "proxy".to_string(),
        ..Default::default()
    };
    let router = Router::new(&router_cfg).unwrap();

    let session = Session {
        target: Address::Domain("baidu.com".to_string(), 443),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    // 没有 GeoSite 数据库，规则不匹配，走默认
    assert_eq!(router.route(&session), "proxy");
}

#[test]
fn router_mixed_rules_priority() {
    let router_cfg = RouterConfig {
        rules: vec![
            RuleConfig {
                rule_type: "domain-full".to_string(),
                values: vec!["specific.example.com".to_string()],
                outbound: "direct".to_string(),
                ..Default::default()
            },
            RuleConfig {
                rule_type: "domain-suffix".to_string(),
                values: vec!["example.com".to_string()],
                outbound: "proxy".to_string(),
                ..Default::default()
            },
        ],
        default: "reject".to_string(),
        ..Default::default()
    };
    let router = Router::new(&router_cfg).unwrap();

    // 精确匹配走 direct
    let session1 = Session {
        target: Address::Domain("specific.example.com".to_string(), 443),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    assert_eq!(router.route(&session1), "direct");

    // 后缀匹配走 proxy
    let session2 = Session {
        target: Address::Domain("other.example.com".to_string(), 443),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    assert_eq!(router.route(&session2), "proxy");

    // 不匹配走默认
    let session3 = Session {
        target: Address::Domain("unknown.org".to_string(), 80),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    assert_eq!(router.route(&session3), "reject");
}

#[test]
fn router_api_accessors() {
    let router_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["cn".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        }],
        default: "proxy".to_string(),
        ..Default::default()
    };
    let router = Router::new(&router_cfg).unwrap();

    assert_eq!(router.rules().len(), 1);
    assert_eq!(router.default_outbound(), "proxy");
}
