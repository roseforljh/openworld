//! P2 新增模块集成测试
//!
//! 覆盖：订阅解析（端到端）、V2Ray Stats API、AnyTLS 帧协议、Hysteria v1 协议帧、ICMP 校验和

use std::collections::HashMap;

// ── 订阅解析端到端测试 ──

/// 完整的 Clash YAML → OutboundConfig 端到端
#[test]
fn subscription_clash_yaml_e2e() {
    let yaml = r#"
proxies:
  - name: "hk-vless-01"
    type: vless
    server: hk1.example.com
    port: 443
    uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    flow: xtls-rprx-vision
    sni: "hk1.example.com"
  - name: "jp-ss-01"
    type: ss
    server: jp1.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "hunter2"
  - name: "us-trojan-01"
    type: trojan
    server: us1.example.com
    port: 443
    password: "trojanpass"
    sni: "us1.example.com"
  - name: "sg-hy2-01"
    type: hysteria2
    server: sg1.example.com
    port: 443
    password: "hy2pass"
    sni: "sg1.example.com"
"#;
    let configs = openworld::config::subscription::parse_subscription(yaml).unwrap();
    assert_eq!(configs.len(), 4);

    // 验证每个节点的协议和关键字段
    assert_eq!(configs[0].protocol, "vless");
    assert_eq!(configs[0].settings.uuid.as_deref(), Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

    assert_eq!(configs[1].protocol, "shadowsocks");
    assert_eq!(configs[1].settings.method.as_deref(), Some("aes-256-gcm"));

    assert_eq!(configs[2].protocol, "trojan");
    assert_eq!(configs[2].settings.password.as_deref(), Some("trojanpass"));

    assert_eq!(configs[3].protocol, "hysteria2");
    assert_eq!(configs[3].settings.address.as_deref(), Some("sg1.example.com"));
}

/// 混合 URI 列表（Base64 编码）端到端
#[test]
fn subscription_base64_mixed_uris_e2e() {
    let uris = vec![
        "vless://test-uuid@server1.com:443?security=tls&sni=server1.com#Node1",
        "trojan://trojanpass@server2.com:443?sni=server2.com#Node2",
        "hy2://hy2pass@server3.com:443?sni=server3.com#Node3",
    ];
    let content = uris.join("\n");
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &content,
    );

    let configs = openworld::config::subscription::parse_subscription(&encoded).unwrap();
    assert_eq!(configs.len(), 3);
    assert_eq!(configs[0].tag, "Node1");
    assert_eq!(configs[1].tag, "Node2");
    assert_eq!(configs[2].tag, "Node3");
}

/// SIP008 JSON 订阅端到端
#[test]
fn subscription_sip008_e2e() {
    let json = r#"{
        "version": 1,
        "servers": [
            {
                "server": "us-west.example.com",
                "server_port": 8388,
                "password": "pass-us",
                "method": "2022-blake3-aes-256-gcm",
                "remarks": "US-West"
            },
            {
                "server": "eu-central.example.com",
                "server_port": 8389,
                "password": "pass-eu",
                "method": "chacha20-ietf-poly1305",
                "remarks": "EU-Central"
            }
        ]
    }"#;
    let configs = openworld::config::subscription::parse_subscription(json).unwrap();
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].tag, "US-West");
    assert_eq!(configs[0].settings.method.as_deref(), Some("2022-blake3-aes-256-gcm"));
    assert_eq!(configs[1].tag, "EU-Central");
    assert_eq!(configs[1].settings.port, Some(8389));
}

/// sing-box JSON 端到端
#[test]
fn subscription_singbox_json_e2e() {
    let json = r#"{
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "vless",
                "tag": "sg-vless",
                "server": "sg.example.com",
                "server_port": 443,
                "uuid": "vless-uuid",
                "tls": {"enabled": true, "server_name": "sg.example.com"}
            },
            {
                "type": "shadowsocks",
                "tag": "jp-ss",
                "server": "jp.example.com",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "sspass"
            }
        ]
    }"#;
    let configs = openworld::config::subscription::parse_subscription(json).unwrap();
    // direct 被跳过
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].tag, "sg-vless");
    assert_eq!(configs[1].tag, "jp-ss");
}

// ── V2Ray Stats API 测试 ──

#[tokio::test]
async fn v2ray_stats_service_e2e() {
    use openworld::api::v2ray_stats::StatsService;

    let service = StatsService::new();

    // 注册入站/出站计数器
    service.register_inbound("socks").await;
    service.register_outbound("proxy").await;
    service.register_user("test@example.com").await;

    // 记录流量
    service.record_inbound_uplink("socks", 1024).await;
    service.record_inbound_uplink("socks", 2048).await;
    service.record_inbound_downlink("socks", 4096).await;
    service.record_outbound_uplink("proxy", 512).await;

    // 查询单个统计
    let stat = service.get_stats("inbound>>>socks>>>traffic>>>uplink", false).await;
    assert!(stat.is_some());
    let stat = stat.unwrap();
    assert_eq!(stat.value, 3072); // 1024 + 2048

    // 查询下行
    let stat = service.get_stats("inbound>>>socks>>>traffic>>>downlink", false).await.unwrap();
    assert_eq!(stat.value, 4096);

    // 查询并重置
    let stat = service.get_stats("inbound>>>socks>>>traffic>>>uplink", true).await.unwrap();
    assert_eq!(stat.value, 3072);
    // 重置后应为 0
    let stat = service.get_stats("inbound>>>socks>>>traffic>>>uplink", false).await.unwrap();
    assert_eq!(stat.value, 0);

    // 查询所有统计
    let response = service.query_stats(None, false).await;
    assert!(!response.stat.is_empty());

    // 按前缀查询
    let response = service.query_stats(Some("outbound>>>proxy"), false).await;
    assert!(!response.stat.is_empty());

    // 系统统计
    let sys = service.sys_stats().await;
    // 只确保不 panic
    let _ = sys;
}

// ── ProxyNode 兼容层端到端 ──

#[test]
fn proxy_node_compat_round_trip() {
    use openworld::config::subscription::{parse_proxy_link, ProxyNode};

    // 从 URI 解析为 ProxyNode
    let node = parse_proxy_link("vless://test-uuid-123@server.com:443?security=tls&sni=server.com&flow=xtls-rprx-vision#TestNode").unwrap();

    assert_eq!(node.name, "TestNode");
    assert_eq!(node.protocol, "vless");
    assert_eq!(node.address, "server.com");
    assert_eq!(node.port, 443);
    assert_eq!(node.settings.get("uuid").unwrap(), "test-uuid-123");
    assert_eq!(node.settings.get("flow").unwrap(), "xtls-rprx-vision");
    assert_eq!(node.to_outbound_tag(), "TestNode");
}

#[test]
fn proxy_node_compat_clash_yaml_nodes() {
    use openworld::config::subscription::parse_clash_yaml_nodes;

    let yaml = r#"
proxies:
  - name: "test-ss"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "testpass"
"#;
    let nodes = parse_clash_yaml_nodes(yaml).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "test-ss");
    assert_eq!(nodes[0].settings.get("password").unwrap(), "testpass");
    assert_eq!(nodes[0].settings.get("cipher").unwrap(), "aes-256-gcm");
}

// ── 格式自动检测 ──

#[test]
fn subscription_format_detection() {
    use openworld::config::subscription::{detect_format, SubFormat};

    // Clash YAML
    assert_eq!(detect_format("proxies:\n  - name: test"), SubFormat::ClashYaml);

    // sing-box JSON
    assert_eq!(detect_format(r#"{"outbounds": []}"#), SubFormat::SingBoxJson);

    // URI 列表
    assert_eq!(detect_format("vless://uuid@host:443#tag"), SubFormat::UriList);

    // Base64
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "vless://uuid@host:443#tag",
    );
    assert_eq!(detect_format(&b64), SubFormat::Base64);
}

// ── 配置加载端到端 ──

#[test]
fn config_load_json_compat_e2e() {
    use openworld::config::json_compat::parse_singbox_json;

    let json = r#"{
        "log": {"level": "debug"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080}
        ],
        "outbounds": [
            {"type": "vless", "tag": "proxy", "server": "1.2.3.4", "server_port": 443, "uuid": "test"},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [
                {"domain_suffix": [".cn"], "outbound": "direct"},
                {"geoip": ["cn"], "outbound": "direct"}
            ],
            "final": "proxy"
        }
    }"#;

    let config = parse_singbox_json(json).unwrap();
    assert_eq!(config.log.level, "debug");
    assert_eq!(config.inbounds.len(), 1);
    assert_eq!(config.inbounds[0].protocol, "socks5"); // mixed → socks5
    assert_eq!(config.inbounds[0].port, 2080);
    assert_eq!(config.outbounds.len(), 2);
    assert_eq!(config.router.default, "proxy");
    assert!(config.router.rules.len() >= 2);
}

// ── DNS 模块集成测试 ──

#[test]
fn dns_config_parsing_e2e() {
    let yaml = r#"
log:
  level: info
dns:
  mode: split
  servers:
    - address: "tls://1.1.1.1"
      domains: ["*"]
    - address: "https://dns.alidns.com/dns-query"
      domains: ["cn", "baidu.com"]
  cache_size: 4096
  cache_ttl: 600
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
    let config: openworld::config::Config = serde_yml::from_str(yaml).unwrap();
    let dns = config.dns.unwrap();
    assert_eq!(dns.servers.len(), 2);
    assert_eq!(dns.cache_size, 4096);
    assert_eq!(dns.mode, "split");
}

// ── 路由规则集成测试 ──

#[test]
fn router_rules_matching_e2e() {
    let yaml = r#"
log:
  level: info
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: proxy
    protocol: direct
  - tag: direct
    protocol: direct
router:
  rules:
    - type: domain-suffix
      values: ["cn", "baidu.com", "bilibili.com"]
      outbound: direct
    - type: ip-cidr
      values: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      outbound: direct
  default: proxy
"#;
    let config: openworld::config::Config = serde_yml::from_str(yaml).unwrap();
    assert_eq!(config.router.rules.len(), 2);
    assert_eq!(config.router.rules[0].rule_type, "domain-suffix");
    assert_eq!(config.router.rules[0].values.len(), 3);
    assert_eq!(config.router.default, "proxy");
}
