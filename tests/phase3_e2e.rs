//! Phase 3 端到端集成测试
//! 覆盖：SOCKS5 TCP/UDP、HTTP CONNECT、Dispatcher TCP/UDP 全链路、Router 多规则优先级、配置反序列化、并发连接。
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use openworld::app::dispatcher::Dispatcher;
use openworld::app::outbound_manager::OutboundManager;
use openworld::app::tracker::ConnectionTracker;
use openworld::common::{Address, UdpPacket};
use openworld::config::types::{OutboundConfig, OutboundSettings, RouterConfig, RuleConfig};
use openworld::dns::DnsResolver;
use openworld::proxy::inbound::http::HttpInbound;
use openworld::proxy::inbound::socks5::Socks5Inbound;
use openworld::proxy::outbound::direct::DirectOutbound;
use openworld::proxy::{InboundHandler, Network, OutboundHandler, Session};
use openworld::router::Router;
use tokio_util::sync::CancellationToken;

struct MockResolver;

#[async_trait::async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1,
        ))])
    }
}

// ============================================================
// 杈呭姪鍑芥暟
// ============================================================

/// 鍚姩涓€涓湰鍦?TCP echo 鏈嶅姟鍣紝杩斿洖鐩戝惉鍦板潃
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// 鍚姩涓€涓湰鍦?UDP echo 鏈嶅姟鍣紝杩斿洖鐩戝惉鍦板潃
async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn make_dispatcher_with_rules(rules: Vec<RuleConfig>, default: &str) -> Dispatcher {
    let router_cfg = RouterConfig {
        rules,
        default: default.to_string(),
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
    let resolver = Arc::new(MockResolver) as Arc<dyn DnsResolver>;
    Dispatcher::new(router, outbound_manager, tracker, resolver, None, CancellationToken::new())
}

// ============================================================
// 1. Direct TCP 鍑虹珯 loopback
// ============================================================

#[tokio::test]
async fn e2e_direct_tcp_loopback() {
    let echo_addr = start_echo_server().await;
    let outbound = DirectOutbound::new("direct".to_string());

    let session = Session {
        target: Address::Ip(echo_addr),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };

    let mut stream = outbound.connect(&session).await.unwrap();

    stream.write_all(b"hello-direct").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello-direct");
}

// ============================================================
// 2. SOCKS5 TCP CONNECT 绔埌绔?// ============================================================

#[tokio::test]
async fn e2e_socks5_tcp_connect() {
    let echo_addr = start_echo_server().await;

    // 鍚姩 SOCKS5 鍏ョ珯
    let socks5 = Socks5Inbound::new("socks-test".to_string(), "127.0.0.1".to_string());
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let dispatcher = Arc::new(make_dispatcher_with_rules(vec![], "direct"));

    // 鏈嶅姟绔細鎺ュ彈涓€涓繛鎺ュ苟璧?dispatcher
    let socks5 = Arc::new(socks5);
    let socks5_clone = socks5.clone();
    let dispatcher_clone = dispatcher.clone();
    let server_task = tokio::spawn(async move {
        let (tcp, source) = socks_listener.accept().await.unwrap();
        let result = socks5_clone.handle(Box::new(tcp), source).await.unwrap();
        dispatcher_clone.dispatch(result).await.unwrap();
    });

    // 瀹㈡埛绔細SOCKS5 鎻℃墜
    let mut client = TcpStream::connect(socks_addr).await.unwrap();

    // 鏂规硶鍗忓晢: VER=5, NMETHODS=1, METHOD=0x00(no auth)
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // CONNECT 璇锋眰: VER=5, CMD=CONNECT, RSV=0, ATYP=1(IPv4), ADDR, PORT
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo_addr {
        SocketAddr::V4(v4) => {
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        _ => panic!("expected v4"),
    }
    client.write_all(&req).await.unwrap();

    // 璇诲彇 CONNECT 鍥炲 (10 bytes)
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05); // VER
    assert_eq!(reply[1], 0x00); // REP=success

    // 閫氳繃闅ч亾鍙戦€佹暟鎹?    client.write_all(b"socks5-e2e-test").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = [0u8; 32];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"socks5-e2e-test");

    drop(client);
    let _ = server_task.await;
}

// ============================================================
// 3. HTTP CONNECT 绔埌绔?// ============================================================

#[tokio::test]
async fn e2e_http_connect() {
    let echo_addr = start_echo_server().await;

    let http_inbound = Arc::new(HttpInbound::new("http-test".to_string()));
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    let dispatcher = Arc::new(make_dispatcher_with_rules(vec![], "direct"));

    let http_clone = http_inbound.clone();
    let dispatcher_clone = dispatcher.clone();
    let server_task = tokio::spawn(async move {
        let (tcp, source) = http_listener.accept().await.unwrap();
        let result = http_clone.handle(Box::new(tcp), source).await.unwrap();
        dispatcher_clone.dispatch(result).await.unwrap();
    });

    let mut client = TcpStream::connect(http_addr).await.unwrap();

    // 鍙戦€?CONNECT 璇锋眰
    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        echo_addr, echo_addr
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // 璇诲彇 200 鍝嶅簲
    let mut resp_buf = [0u8; 256];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
    assert!(
        resp_str.contains("200"),
        "expected 200 response, got: {resp_str}"
    );

    // 閫氳繃闅ч亾鍙戦€佹暟鎹?    client.write_all(b"http-connect-e2e").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = [0u8; 32];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"http-connect-e2e");

    drop(client);
    let _ = server_task.await;
}

// ============================================================
// 4. Dispatcher TCP 鍏ㄩ摼璺紙璺敱 -> 鍑虹珯 -> relay锛?// ============================================================

#[tokio::test]
async fn e2e_dispatcher_tcp_relay() {
    let echo_addr = start_echo_server().await;

    let dispatcher = make_dispatcher_with_rules(vec![], "direct");

    let session = Session {
        target: Address::Ip(echo_addr),
        source: Some("127.0.0.1:9999".parse().unwrap()),
        inbound_tag: "test-in".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };

    // 鍒涘缓涓€瀵?connected TCP streams 妯℃嫙鍏ョ珯
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let connect_task = tokio::spawn(async move { TcpStream::connect(local_addr).await.unwrap() });

    let (server_side, _) = listener.accept().await.unwrap();
    let mut client_side = connect_task.await.unwrap();

    let inbound_result = openworld::proxy::InboundResult {
        session,
        stream: Box::new(server_side),
        udp_transport: None,
    };

    let dispatch_task = tokio::spawn(async move { dispatcher.dispatch(inbound_result).await });

    // 閫氳繃 client_side 鍙戦€佹暟鎹紝搴旇琚?relay 鍒?echo server 骞惰繑鍥?    client_side.write_all(b"dispatcher-tcp-e2e").await.unwrap();
    client_side.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = client_side.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"dispatcher-tcp-e2e");

    drop(client_side);
    let _ = dispatch_task.await;
}

// ============================================================
// 5. Router 澶氳鍒欎紭鍏堢骇
// ============================================================

#[test]
fn e2e_router_multi_rule_first_match() {
    let router_cfg = RouterConfig {
        rules: vec![
            RuleConfig {
                rule_type: "domain-full".to_string(),
                values: vec!["exact.example.com".to_string()],
                outbound: "direct".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
            RuleConfig {
                rule_type: "domain-suffix".to_string(),
                values: vec!["example.com".to_string()],
                outbound: "direct".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
            RuleConfig {
                rule_type: "domain-keyword".to_string(),
                values: vec!["google".to_string()],
                outbound: "direct".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
            RuleConfig {
                rule_type: "ip-cidr".to_string(),
                values: vec!["10.0.0.0/8".to_string()],
                outbound: "direct".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
        ],
        default: "direct".to_string(),
        ..Default::default()
    };
    let router = Router::new(&router_cfg).unwrap();

    let make_session = |target: Address| Session {
        target,
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };

    // domain-full 绮剧‘鍖归厤
    assert_eq!(
        router.route(&make_session(Address::Domain(
            "exact.example.com".to_string(),
            443
        ))),
        "direct"
    );

    // domain-suffix 鍚庣紑鍖归厤
    assert_eq!(
        router.route(&make_session(Address::Domain(
            "sub.example.com".to_string(),
            443
        ))),
        "direct"
    );

    // domain-keyword 关键字匹配
    assert_eq!(
        router.route(&make_session(Address::Domain(
            "www.google.com".to_string(),
            443
        ))),
        "direct"
    );

    // ip-cidr 鍖归厤
    assert_eq!(
        router.route(&make_session(Address::Ip("10.1.2.3:80".parse().unwrap()))),
        "direct"
    );

    // 涓嶅尮閰嶄换浣曡鍒?-> default
    assert_eq!(
        router.route(&make_session(Address::Domain(
            "unknown.org".to_string(),
            80
        ))),
        "direct"
    );
    assert_eq!(
        router.route(&make_session(Address::Ip("8.8.8.8:53".parse().unwrap()))),
        "direct"
    );
}

// ============================================================
// 6. Config 鍙嶅簭鍒楀寲锛歊eality 瀛楁
// ============================================================

#[test]
fn e2e_config_deserialize_reality_fields() {
    let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: vless-reality
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      security: reality
      server_name: "www.microsoft.com"
      public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      short_id: "aabbccdd"
      sni: "www.microsoft.com"
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
    let config: openworld::config::types::Config = serde_yml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    let vless = &config.outbounds[0].settings;
    assert_eq!(vless.security.as_deref(), Some("reality"));
    assert_eq!(vless.server_name.as_deref(), Some("www.microsoft.com"));
    assert_eq!(
        vless.public_key.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
    assert_eq!(vless.short_id.as_deref(), Some("aabbccdd"));
}

#[test]
fn e2e_config_deserialize_hysteria2_fields() {
    let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: hy2-out
    protocol: hysteria2
    settings:
      address: "5.6.7.8"
      port: 443
      password: "test-password"
      sni: "hy2.example.com"
      allow_insecure: true
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
    let config: openworld::config::types::Config = serde_yml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    let hy2 = &config.outbounds[0].settings;
    assert_eq!(hy2.password.as_deref(), Some("test-password"));
    assert_eq!(hy2.sni.as_deref(), Some("hy2.example.com"));
    assert!(hy2.allow_insecure);
}

// ============================================================
// 7. SOCKS5 UDP ASSOCIATE 绔埌绔?// ============================================================

#[tokio::test]
async fn e2e_socks5_udp_associate() {
    let udp_echo_addr = start_udp_echo_server().await;

    let socks5 = Arc::new(Socks5Inbound::new(
        "socks-udp".to_string(),
        "127.0.0.1".to_string(),
    ));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let dispatcher = Arc::new(make_dispatcher_with_rules(vec![], "direct"));

    let socks5_clone = socks5.clone();
    let dispatcher_clone = dispatcher.clone();
    let server_task = tokio::spawn(async move {
        let (tcp, source) = socks_listener.accept().await.unwrap();
        let result = socks5_clone.handle(Box::new(tcp), source).await.unwrap();
        assert_eq!(result.session.network, Network::Udp);
        assert!(result.udp_transport.is_some());
        dispatcher_clone.dispatch(result).await.unwrap();
    });

    // 瀹㈡埛绔?TCP 鎺у埗杩炴帴
    let mut client = TcpStream::connect(socks_addr).await.unwrap();

    // 鏂规硶鍗忓晢
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // UDP ASSOCIATE 璇锋眰: CMD=0x03, ATYP=1, ADDR=0.0.0.0, PORT=0
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    // 璇诲彇鍥炲: VER(1) + REP(1) + RSV(1) + ATYP(1) + ADDR(4/16) + PORT(2)
    let mut reply_head = [0u8; 4];
    client.read_exact(&mut reply_head).await.unwrap();
    assert_eq!(reply_head[0], 0x05); // VER
    assert_eq!(reply_head[1], 0x00); // REP=success

    let atyp = reply_head[3];
    let relay_addr: SocketAddr = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await.unwrap();
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await.unwrap();
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                port,
            )
        }
        0x04 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await.unwrap();
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await.unwrap();
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)), port)
        }
        _ => panic!("unexpected atyp: {atyp}"),
    };

    // 瀹㈡埛绔?UDP socket
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 鏋勯€?SOCKS5 UDP 鏁版嵁鎶? [RSV:2][FRAG:1][ATYP+ADDR+PORT][DATA]
    let mut udp_pkt = vec![0x00, 0x00, 0x00]; // RSV + FRAG=0
    match udp_echo_addr {
        SocketAddr::V4(v4) => {
            udp_pkt.push(0x01);
            udp_pkt.extend_from_slice(&v4.ip().octets());
            udp_pkt.extend_from_slice(&v4.port().to_be_bytes());
        }
        _ => panic!("expected v4"),
    }
    udp_pkt.extend_from_slice(b"udp-e2e-payload");

    client_udp.send_to(&udp_pkt, relay_addr).await.unwrap();

    // 绛夊緟鍥炲
    let mut recv_buf = [0u8; 512];
    let tokio_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_udp.recv_from(&mut recv_buf),
    )
    .await;

    let (n, _from) = tokio_result.expect("UDP reply timed out").unwrap();
    let reply_data = &recv_buf[..n];

    // 瑙ｆ瀽 SOCKS5 UDP 鍥炲澶?    assert!(reply_data.len() >= 3, "reply too short");
    assert_eq!(reply_data[2], 0x00); // FRAG=0

    let (addr, addr_len) = Address::parse_socks5_udp_addr(&reply_data[3..]).unwrap();
    let payload = &reply_data[3 + addr_len..];

    // echo server 搴旇鍘熸牱杩斿洖
    assert_eq!(payload, b"udp-e2e-payload");
    assert_eq!(addr, Address::Ip(udp_echo_addr));

    // 鍏抽棴 TCP 鎺у埗杩炴帴锛岃Е鍙?dispatcher 娓呯悊
    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

// ============================================================
// 8. 骞跺彂 TCP 杩炴帴
// ============================================================

#[tokio::test]
async fn e2e_concurrent_tcp_connections() {
    let echo_addr = start_echo_server().await;
    let outbound = Arc::new(DirectOutbound::new("direct".to_string()));

    let mut handles = Vec::new();
    for i in 0..10u32 {
        let outbound = outbound.clone();
        let handle = tokio::spawn(async move {
            let session = Session {
                target: Address::Ip(echo_addr),
                source: None,
                inbound_tag: format!("conn-{i}"),
                network: Network::Tcp,
                sniff: false,
                detected_protocol: None,
            };

            let mut stream = outbound.connect(&session).await.unwrap();
            let msg = format!("concurrent-{i}");
            stream.write_all(msg.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            let mut buf = vec![0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ============================================================
// 9. Direct UDP 澶氱洰鏍?NAT 琛屼负
// ============================================================

#[tokio::test]
async fn e2e_direct_udp_multi_target() {
    let echo1 = start_udp_echo_server().await;
    let echo2 = start_udp_echo_server().await;

    let outbound = DirectOutbound::new("direct".to_string());
    let session = Session {
        target: Address::Ip(echo1),
        source: None,
        inbound_tag: "test".to_string(),
        network: Network::Udp,
        sniff: false,
        detected_protocol: None,
    };

    let transport = outbound.connect_udp(&session).await.unwrap();

    // 鍙戦€佸埌 echo1
    transport
        .send(UdpPacket {
            addr: Address::Ip(echo1),
            data: Bytes::from_static(b"to-echo1"),
        })
        .await
        .unwrap();

    let reply1 = transport.recv().await.unwrap();
    assert_eq!(reply1.data.as_ref(), b"to-echo1");

    // 鍙戦€佸埌 echo2锛堝悓涓€涓?transport锛屼笉鍚岀洰鏍囷級
    transport
        .send(UdpPacket {
            addr: Address::Ip(echo2),
            data: Bytes::from_static(b"to-echo2"),
        })
        .await
        .unwrap();

    let reply2 = transport.recv().await.unwrap();
    assert_eq!(reply2.data.as_ref(), b"to-echo2");
}

// ============================================================
// 10. SOCKS5 TCP CONNECT 鍩熷悕鐩爣
// ============================================================

#[tokio::test]
async fn e2e_socks5_tcp_connect_domain() {
    let echo_addr = start_echo_server().await;

    let socks5 = Arc::new(Socks5Inbound::new(
        "socks-domain".to_string(),
        "127.0.0.1".to_string(),
    ));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let dispatcher = Arc::new(make_dispatcher_with_rules(vec![], "direct"));

    let socks5_clone = socks5.clone();
    let dispatcher_clone = dispatcher.clone();
    let server_task = tokio::spawn(async move {
        let (tcp, source) = socks_listener.accept().await.unwrap();
        let result = socks5_clone.handle(Box::new(tcp), source).await.unwrap();
        dispatcher_clone.dispatch(result).await.unwrap();
    });

    let mut client = TcpStream::connect(socks_addr).await.unwrap();

    // 鏂规硶鍗忓晢
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // CONNECT 璇锋眰: ATYP=0x03(Domain), domain="127.0.0.1", port=echo_addr.port()
    // 娉ㄦ剰锛氳繖閲岀敤 "localhost" 浣滀负鍩熷悕锛屽畠浼氳 DNS 瑙ｆ瀽鍒?127.0.0.1
    let domain = b"localhost";
    let port = echo_addr.port();
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(domain.len() as u8);
    req.extend_from_slice(domain);
    req.extend_from_slice(&port.to_be_bytes());
    client.write_all(&req).await.unwrap();

    // 璇诲彇鍥炲
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);

    // 閫氳繃闅ч亾鍙戦€佹暟鎹?    client.write_all(b"domain-connect-test").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = [0u8; 32];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain-connect-test");

    drop(client);
    let _ = server_task.await;
}
