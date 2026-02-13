#![allow(
    clippy::field_reassign_with_default,
    clippy::redundant_field_names,
    clippy::needless_return
)]
//! Phase 13: P1 新增模块集成测试
//!
//! 覆盖：SSM API、WireGuard Noise 握手、NTP 协议嗅探、
//!       TUN Loopback 检测、TLS 证书热重载、DoT 连接复用

use std::sync::Arc;

// ── SSM API 端到端测试 ──

struct MockResolver;

#[async_trait::async_trait]
impl openworld::dns::DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1,
        ))])
    }
}

/// 启动包含 SSM 路由的测试 API 服务器
async fn start_ssm_api() -> String {
    use openworld::api;
    use openworld::app::dispatcher::Dispatcher;
    use openworld::app::outbound_manager::OutboundManager;
    use openworld::app::tracker::ConnectionTracker;
    use openworld::config::types::{OutboundConfig, OutboundSettings, RouterConfig};
    use openworld::dns::DnsResolver;
    use openworld::router::Router;
    use tokio_util::sync::CancellationToken;

    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        ..Default::default()
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());
    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];
    let outbound_manager = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(
        router,
        outbound_manager,
        tracker,
        Arc::new(MockResolver) as Arc<dyn DnsResolver>,
        None,
        CancellationToken::new(),
    ));

    let state = api::handlers::AppState {
        dispatcher,
        secret: None,
        config_path: None,
        log_broadcaster: api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
        ss_inbound: None,
    };

    let app = axum::Router::new()
        .route(
            "/ssm/users",
            axum::routing::get(api::handlers::ssm_list_users).post(api::handlers::ssm_add_user),
        )
        .route(
            "/ssm/users/{name}",
            axum::routing::delete(api::handlers::ssm_remove_user),
        )
        .route(
            "/ssm/users/{name}/reset",
            axum::routing::post(api::handlers::ssm_reset_traffic),
        )
        .route("/ssm/stats", axum::routing::get(api::handlers::ssm_stats))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn ssm_api_no_inbound_returns_not_found() {
    let base = start_ssm_api().await;
    let resp = reqwest::get(format!("{}/ssm/users", base)).await.unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn ssm_stats_no_inbound() {
    let base = start_ssm_api().await;
    let resp = reqwest::get(format!("{}/ssm/stats", base)).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn ssm_add_user_no_inbound() {
    let base = start_ssm_api().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/ssm/users", base))
        .json(&serde_json::json!({"name": "test", "password": "123456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn ssm_remove_user_no_inbound() {
    let base = start_ssm_api().await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}/ssm/users/testuser", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn ssm_reset_traffic_no_inbound() {
    let base = start_ssm_api().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/ssm/users/testuser/reset", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── WireGuard Noise 协议测试 ──

#[test]
fn wireguard_noise_handshake_init_parse_roundtrip() {
    use openworld::proxy::outbound::wireguard::noise::*;

    let (client_priv, client_pub) = generate_keypair();
    let (server_priv, server_pub) = generate_keypair();
    let psk = [0u8; 32];

    // 客户端创建握手 init
    let client_keys = WireGuardKeys {
        private_key: client_priv,
        public_key: client_pub,
        peer_public_key: server_pub,
        preshared_key: psk,
    };
    let (init_msg, _ck, _h) = create_handshake_init(&client_keys, 42).unwrap();
    assert_eq!(init_msg.len(), 148);

    // 服务端解析握手 init
    let server_keys = WireGuardKeys {
        private_key: server_priv,
        public_key: server_pub,
        peer_public_key: client_pub,
        preshared_key: psk,
    };
    let (sender_index, peer_pk, _ck, _h) = parse_handshake_init(&init_msg, &server_keys).unwrap();
    assert_eq!(sender_index, 42);
    assert_eq!(peer_pk.as_bytes(), client_pub.as_bytes());
}

#[test]
fn wireguard_noise_full_handshake_creates_resp() {
    use openworld::proxy::outbound::wireguard::noise::*;

    let (client_priv, client_pub) = generate_keypair();
    let (server_priv, server_pub) = generate_keypair();
    let psk = [0xABu8; 32];

    let client_keys = WireGuardKeys {
        private_key: client_priv,
        public_key: client_pub,
        peer_public_key: server_pub,
        preshared_key: psk,
    };
    let (init_msg, _ck, _h) = create_handshake_init(&client_keys, 100).unwrap();

    let server_keys = WireGuardKeys {
        private_key: server_priv,
        public_key: server_pub,
        peer_public_key: client_pub,
        preshared_key: psk,
    };
    let (peer_sender_idx, _peer_pk, ck, h) = parse_handshake_init(&init_msg, &server_keys).unwrap();
    assert_eq!(peer_sender_idx, 100);

    let eph_bytes: [u8; 32] = init_msg[8..40].try_into().unwrap();
    let (resp_msg, server_transport) =
        create_handshake_resp(&server_keys, 200, peer_sender_idx, ck, h, &eph_bytes).unwrap();

    // 验证 response 消息格式
    assert_eq!(resp_msg.len(), 92);
    let resp_type = u32::from_le_bytes(resp_msg[0..4].try_into().unwrap());
    assert_eq!(resp_type, 2); // MSG_TYPE_HANDSHAKE_RESP

    let resp_sender = u32::from_le_bytes(resp_msg[4..8].try_into().unwrap());
    assert_eq!(resp_sender, 200);

    let resp_receiver = u32::from_le_bytes(resp_msg[8..12].try_into().unwrap());
    assert_eq!(resp_receiver, 100);

    // 验证 transport keys
    assert_ne!(server_transport.send_key, [0u8; 32]);
    assert_ne!(server_transport.recv_key, [0u8; 32]);
    assert_ne!(server_transport.send_key, server_transport.recv_key);
}

#[test]
fn wireguard_noise_server_encrypt_transport() {
    use openworld::proxy::outbound::wireguard::noise::*;

    let (client_priv, client_pub) = generate_keypair();
    let (server_priv, server_pub) = generate_keypair();

    let client_keys = WireGuardKeys {
        private_key: client_priv,
        public_key: client_pub,
        peer_public_key: server_pub,
        preshared_key: [0u8; 32],
    };
    let (init_msg, _, _) = create_handshake_init(&client_keys, 1).unwrap();

    let server_keys = WireGuardKeys {
        private_key: server_priv,
        public_key: server_pub,
        peer_public_key: client_pub,
        preshared_key: [0u8; 32],
    };
    let (_, _, ck, h) = parse_handshake_init(&init_msg, &server_keys).unwrap();
    let eph: [u8; 32] = init_msg[8..40].try_into().unwrap();
    let (_, mut transport) = create_handshake_resp(&server_keys, 2, 1, ck, h, &eph).unwrap();

    let plaintext = b"hello wireguard endpoint";
    let encrypted = encrypt_transport(&mut transport, plaintext).unwrap();
    assert!(encrypted.len() > 16 + plaintext.len());
    assert_eq!(transport.send_counter, 1);
}

#[test]
fn wireguard_noise_bad_init_rejected() {
    use openworld::proxy::outbound::wireguard::noise::*;

    let (server_priv, server_pub) = generate_keypair();
    let (_, wrong_pub) = generate_keypair();

    let server_keys = WireGuardKeys {
        private_key: server_priv,
        public_key: server_pub,
        peer_public_key: wrong_pub,
        preshared_key: [0u8; 32],
    };

    // 随机数据应被拒绝
    let bad_data = vec![0x01, 0x00, 0x00, 0x00]; // type=1 but too short
    let mut full_bad = bad_data;
    full_bad.extend_from_slice(&[0u8; 144]); // 填充到 148 字节
    let result = parse_handshake_init(&full_bad, &server_keys);
    assert!(result.is_err());
}

// ── NTP 协议嗅探测试 ──

#[test]
fn ntp_sniff_client_mode_detected() {
    use openworld::proxy::sniff::{detect_protocol, is_ntp};

    // NTP 客户端包: VN=4, Mode=3 → 0x23
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x23;
    assert!(is_ntp(&pkt));
    assert_eq!(detect_protocol(&pkt), Some("ntp"));
}

#[test]
fn ntp_sniff_server_mode_detected() {
    use openworld::proxy::sniff::{detect_protocol, is_ntp};

    // NTP 服务端响应: VN=4, Mode=4 → 0x24
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x24;
    assert!(is_ntp(&pkt));
    assert_eq!(detect_protocol(&pkt), Some("ntp"));
}

#[test]
fn ntp_sniff_v3_broadcast() {
    use openworld::proxy::sniff::is_ntp;

    // NTPv3 broadcast: VN=3, Mode=5 → 0b00_011_101 = 0x1D
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x1D;
    assert!(is_ntp(&pkt));
}

#[test]
fn ntp_sniff_too_short() {
    use openworld::proxy::sniff::is_ntp;
    assert!(!is_ntp(&[0x23; 10])); // 只 10 字节
}

#[test]
fn ntp_sniff_invalid_version() {
    use openworld::proxy::sniff::is_ntp;

    let mut pkt = vec![0u8; 48];
    // VN=5 (无效), Mode=3 → 0b00_101_011 = 0x2B
    pkt[0] = 0x2B;
    assert!(!is_ntp(&pkt));
}

#[test]
fn ntp_sniff_not_ntp_random() {
    use openworld::proxy::sniff::detect_protocol;
    let random = vec![0x00, 0x01, 0x02, 0x03, 0x04];
    assert_ne!(detect_protocol(&random), Some("ntp"));
}

#[test]
fn ntp_timestamp_parsing_server() {
    use openworld::proxy::sniff::parse_ntp_timestamp;

    // NTP 服务端响应 (Mode=4)
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x24; // VN=4, Mode=4
                   // Transmit Timestamp 在 offset 40-47
    pkt[40] = 0xE2;
    pkt[41] = 0xD2;
    pkt[42] = 0x5F;
    pkt[43] = 0xAB;

    let result = parse_ntp_timestamp(&pkt);
    assert!(result.is_some());
    let (secs, _frac) = result.unwrap();
    assert!(secs > 0);
}

#[test]
fn ntp_timestamp_client_mode_returns_none() {
    use openworld::proxy::sniff::parse_ntp_timestamp;

    // 客户端模式 (Mode=3) 不应返回时间戳
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x23;
    assert!(parse_ntp_timestamp(&pkt).is_none());
}

#[test]
fn ntp_timestamp_zero_returns_none() {
    use openworld::proxy::sniff::parse_ntp_timestamp;

    // 时间戳全零应返回 None
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x24;
    // offset 40-47 全是 0
    assert!(parse_ntp_timestamp(&pkt).is_none());
}

// ── TUN Loopback 检测测试 ──

#[test]
fn tun_stack_config_loopback_default_false() {
    use openworld::proxy::inbound::tun_stack::TunStackConfig;
    let config = TunStackConfig::default();
    assert!(!config.allow_loopback, "loopback 默认应禁止");
}

#[test]
fn tun_stack_config_loopback_can_enable() {
    use openworld::proxy::inbound::tun_stack::TunStackConfig;
    let mut config = TunStackConfig::default();
    config.allow_loopback = true;
    assert!(config.allow_loopback);
}

#[test]
fn tun_stack_config_defaults_sane() {
    use openworld::proxy::inbound::tun_stack::TunStackConfig;
    let config = TunStackConfig::default();
    assert!(config.sniff);
    assert!(config.dns_hijack_enabled);
    assert!(config.max_tcp_connections > 0);
    assert!(config.max_udp_sessions > 0);
}

// ── TLS 证书热重载测试 ──

#[test]
fn tls_cert_reloader_creation_with_interval() {
    use openworld::common::tls_reload::CertReloader;
    use std::time::Duration;

    let reloader =
        CertReloader::new("/tmp/cert.pem", "/tmp/key.pem").with_interval(Duration::from_secs(60));
    drop(reloader);
}

#[test]
fn tls_cert_reloader_load_nonexistent_fails() {
    use openworld::common::tls_reload::CertReloader;

    let reloader = CertReloader::new("/nonexistent/path/cert.pem", "/nonexistent/path/key.pem");
    let result = reloader.load_initial();
    assert!(result.is_err(), "不存在的证书文件应导致加载失败");
}

#[tokio::test]
async fn tls_reloadable_config_replace() {
    use openworld::common::tls_reload::ReloadableServerConfig;

    // 用 rcgen 生成自签名证书
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .unwrap();

    let reloadable = ReloadableServerConfig::new(server_config);
    let config1 = reloadable.current().await;

    // 生成新证书并替换
    let cert2 = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
    let cert2_der = cert2.cert.der().to_vec();
    let key2_der = cert2.key_pair.serialize_der();

    let provider2 = Arc::new(rustls::crypto::ring::default_provider());
    let new_config = rustls::ServerConfig::builder_with_provider(provider2)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert2_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key2_der,
            )),
        )
        .unwrap();

    reloadable.replace(new_config).await;
    let config2 = reloadable.current().await;
    assert!(!Arc::ptr_eq(&config1, &config2), "替换后 config 应不同");
}

// ── DoT 连接复用配置测试 ──

#[test]
fn dns_dot_resolver_creation() {
    use openworld::dns::resolver::HickoryResolver;
    let resolver = HickoryResolver::new("tls://8.8.8.8");
    assert!(resolver.is_ok(), "DoT 解析器创建应成功");
}

#[test]
fn dns_dot_with_port() {
    use openworld::dns::resolver::HickoryResolver;
    let resolver = HickoryResolver::new("tls://1.1.1.1:853");
    assert!(resolver.is_ok());
}

#[test]
fn dns_udp_resolver_creation() {
    use openworld::dns::resolver::HickoryResolver;
    let resolver = HickoryResolver::new("8.8.8.8");
    assert!(resolver.is_ok());
}

#[test]
fn dns_quic_resolver_creation() {
    use openworld::dns::resolver::HickoryResolver;
    let resolver = HickoryResolver::new("quic://8.8.8.8");
    // DNS-over-QUIC is no longer supported (ring 0.16 compat issue)
    assert!(resolver.is_err());
}

#[test]
fn dns_invalid_address_fails() {
    use openworld::dns::resolver::HickoryResolver;
    let resolver = HickoryResolver::new("invalid://broken");
    assert!(resolver.is_err());
}

// ── WireGuard 配置解析测试 ──

#[test]
fn wireguard_inbound_config_parsing() {
    use openworld::config::types::InboundConfig;

    let json = serde_json::json!({
        "tag": "wg-in",
        "protocol": "wireguard",
        "listen": "0.0.0.0",
        "port": 51820,
        "settings": {
            "private-key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            "wg-peers": [
                {"public-key": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}
            ]
        }
    });

    let config: InboundConfig = serde_json::from_value(json).unwrap();
    assert_eq!(config.tag, "wg-in");
    assert_eq!(config.port, 51820);
    assert!(config.settings.private_key.is_some());
    let peers = config.settings.wg_peers.as_ref().unwrap();
    assert_eq!(peers.len(), 1);
}

#[test]
fn wireguard_inbound_config_with_psk() {
    use openworld::config::types::InboundConfig;

    let json = serde_json::json!({
        "tag": "wg-psk",
        "protocol": "wireguard",
        "listen": "0.0.0.0",
        "port": 51821,
        "settings": {
            "private-key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            "preshared-key": "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=",
            "wg-peers": [
                {"public-key": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}
            ]
        }
    });

    let config: InboundConfig = serde_json::from_value(json).unwrap();
    assert!(config.settings.preshared_key.is_some());
}

#[test]
fn inbound_config_backward_compatible() {
    use openworld::config::types::InboundConfig;

    // 旧配置（无 WG 字段）应正常解析
    let json = serde_json::json!({
        "tag": "socks-in",
        "protocol": "socks5",
        "listen": "0.0.0.0",
        "port": 1080,
        "settings": {}
    });

    let config: InboundConfig = serde_json::from_value(json).unwrap();
    assert!(config.settings.private_key.is_none());
    assert!(config.settings.wg_peers.is_none());
    assert!(config.settings.preshared_key.is_none());
}

// ── SSM UserInfo 序列化测试 ──

#[test]
fn ssm_user_info_serialization() {
    use openworld::proxy::inbound::shadowsocks::SsmUserInfo;

    let info = SsmUserInfo {
        name: "alice".to_string(),
        traffic_up: 1024,
        traffic_down: 2048,
    };

    let json = serde_json::to_value(&info).unwrap();
    assert_eq!(json["name"], "alice");
    assert_eq!(json["traffic_up"], 1024);
    assert_eq!(json["traffic_down"], 2048);
}
