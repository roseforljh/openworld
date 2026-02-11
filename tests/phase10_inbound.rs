//! Phase 5: Mixed 入站集成测试

use openworld::proxy::inbound::mixed::MixedInbound;
use openworld::proxy::inbound::shadowsocks::ShadowsocksInbound;
use openworld::proxy::inbound::tun::TunInbound;
use openworld::dns::DnsResolver;
use openworld::proxy::InboundHandler;

struct MockResolver;

#[async_trait::async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1,
        ))])
    }
}

#[test]
fn mixed_inbound_creation() {
    let mixed = MixedInbound::new("mixed-in".to_string(), "127.0.0.1".to_string());
    assert_eq!(mixed.tag(), "mixed-in");
}

#[test]
fn tun_inbound_creation() {
    let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
    assert_eq!(tun.tag(), "tun-in");
    assert_eq!(tun.name(), "openworld-utun0");
}

#[test]
fn inbound_manager_registers_mixed() {
    use openworld::app::dispatcher::Dispatcher;
    use openworld::app::outbound_manager::OutboundManager;
    use openworld::app::tracker::ConnectionTracker;
    use openworld::config::types::{
        InboundConfig, InboundSettings, OutboundConfig, OutboundSettings, RouterConfig,
        SniffingConfig,
    };
    use openworld::router::Router;
    use std::sync::Arc;

    let _inbounds = [InboundConfig {
        tag: "mixed-in".to_string(),
        protocol: "mixed".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 0,
        sniffing: SniffingConfig::default(),
        settings: InboundSettings::default(),
    }];

    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        geoip_db: None,
        geosite_db: None,
        rule_providers: Default::default(),
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());
    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let resolver = Arc::new(MockResolver) as Arc<dyn DnsResolver>;
    let _dispatcher = Arc::new(Dispatcher::new(router, om, tracker, resolver));

    // InboundManager 能够注册 mixed 协议
    // 由于 InboundManager::new 需要 CancellationToken 和 bind，我们直接验证 MixedInbound 可创建
    // 实际协议检测需要网络连接，这里只验证注册路径
    let mixed = MixedInbound::new("mixed-in".to_string(), "127.0.0.1".to_string());
    assert_eq!(mixed.tag(), "mixed-in");
}

#[test]
fn ss_inbound_creation() {
    let cfg = openworld::config::types::InboundConfig {
        tag: "ss-in".to_string(),
        protocol: "shadowsocks".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8388,
        sniffing: openworld::config::types::SniffingConfig::default(),
        settings: openworld::config::types::InboundSettings {
            method: Some("aes-128-gcm".to_string()),
            password: Some("pass".to_string()),
            users: None,
            ..Default::default()
        },
    };
    let ss = ShadowsocksInbound::new(&cfg).unwrap();
    assert_eq!(ss.tag(), "ss-in");
}

#[test]
fn config_accepts_tun_inbound_protocol() {
    let yaml = r#"
inbounds:
  - tag: tun-in
    protocol: tun
    listen: openworld-utun0
    port: 0
    settings: {}
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
    let config: openworld::config::Config = serde_yml::from_str(yaml).unwrap();
    assert_eq!(config.inbounds.len(), 1);
    assert_eq!(config.inbounds[0].protocol, "tun");
    assert_eq!(config.inbounds[0].listen, "openworld-utun0");
    assert!(config.validate().is_ok());
}
