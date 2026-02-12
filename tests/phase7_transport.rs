//! Phase 4C: H2/gRPC 传输层测试

use std::future::poll_fn;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use openworld::common::Address;
use openworld::config::types::{TlsConfig, TransportConfig};
use openworld::proxy::transport::{
    build_transport, grpc::GrpcTransport, h2::H2Transport, StreamTransport,
};

/// 启动 plaintext H2 echo 服务器
///
/// 请求处理必须 spawn 到独立 task，让 accept 循环持续驱动 H2 Connection 的 I/O。
async fn start_h2_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut conn = h2::server::handshake(tcp).await.unwrap();

        while let Some(result) = conn.accept().await {
            let (request, mut respond) = result.unwrap();
            tokio::spawn(async move {
                let mut body = request.into_body();

                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();

                while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
                    let chunk = chunk.unwrap();
                    let _ = body.flow_control().release_capacity(chunk.len());
                    send.send_data(chunk, false).unwrap();
                }
                let _ = send.send_data(Bytes::new(), true);
            });
        }
    });

    addr
}

// --- build_transport 工厂测试 ---

#[test]
fn build_transport_h2_ok() {
    let tc = TransportConfig {
        transport_type: "h2".to_string(),
        path: Some("/tunnel".to_string()),
        host: Some("example.com".to_string()),
        headers: None,
        service_name: None,
    };
    let tls = TlsConfig::default();
    assert!(build_transport("1.2.3.4", 443, &tc, &tls).is_ok());
}

#[test]
fn build_transport_grpc_ok() {
    let tc = TransportConfig {
        transport_type: "grpc".to_string(),
        path: None,
        host: Some("example.com".to_string()),
        headers: None,
        service_name: Some("MyService".to_string()),
    };
    let tls = TlsConfig::default();
    assert!(build_transport("1.2.3.4", 443, &tc, &tls).is_ok());
}

#[test]
fn build_transport_unsupported_type_fails() {
    let tc = TransportConfig {
        transport_type: "quic".to_string(),
        path: None,
        host: None,
        headers: None,
        service_name: None,
    };
    let tls = TlsConfig::default();
    assert!(build_transport("1.2.3.4", 443, &tc, &tls).is_err());
}

#[test]
fn build_transport_grpc_default_service_name() {
    let tc = TransportConfig {
        transport_type: "grpc".to_string(),
        path: None,
        host: None,
        headers: None,
        service_name: None, // 默认使用 GunService
    };
    let tls = TlsConfig::default();
    assert!(build_transport("1.2.3.4", 443, &tc, &tls).is_ok());
}

// --- H2 传输 echo 测试 ---

#[tokio::test]
async fn h2_transport_echo() {
    let addr = start_h2_echo_server().await;

    let transport = H2Transport::new(
        "127.0.0.1".to_string(),
        addr.port(),
        Some("/test".to_string()),
        None,
        None,
        None,
    );

    let target = Address::Domain("dummy.test".to_string(), 80);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = transport.connect(&target).await.unwrap();

        stream.write_all(b"hello h2 world").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello h2 world");
    })
    .await;

    assert!(result.is_ok(), "h2 echo test timed out");
}

#[tokio::test]
async fn h2_transport_multi_write() {
    let addr = start_h2_echo_server().await;

    let transport = H2Transport::new(
        "127.0.0.1".to_string(),
        addr.port(),
        Some("/multi".to_string()),
        None,
        None,
        None,
    );

    let target = Address::Domain("dummy.test".to_string(), 80);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = transport.connect(&target).await.unwrap();

        // 多次写入
        stream.write_all(b"part1").await.unwrap();
        stream.write_all(b"part2").await.unwrap();
        stream.write_all(b"part3").await.unwrap();
        stream.shutdown().await.unwrap();

        // 读取所有回显数据
        let mut all = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, b"part1part2part3");
    })
    .await;

    assert!(result.is_ok(), "h2 multi-write test timed out");
}

// --- gRPC 传输 echo 测试 ---

#[tokio::test]
async fn grpc_transport_echo() {
    // gRPC 也使用 H2 echo 服务器（gRPC 帧在客户端侧添加/剥离）
    let addr = start_h2_echo_server().await;

    let transport = GrpcTransport::new(
        "127.0.0.1".to_string(),
        addr.port(),
        Some("TestService".to_string()),
        None,
        None,
        None,
    );

    let target = Address::Domain("dummy.test".to_string(), 80);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = transport.connect(&target).await.unwrap();

        stream.write_all(b"grpc payload").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"grpc payload");
    })
    .await;

    assert!(result.is_ok(), "grpc echo test timed out");
}

#[tokio::test]
async fn grpc_transport_multi_write() {
    let addr = start_h2_echo_server().await;

    let transport = GrpcTransport::new(
        "127.0.0.1".to_string(),
        addr.port(),
        None, // 默认 GunService
        None,
        None,
        None,
    );

    let target = Address::Domain("dummy.test".to_string(), 80);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = transport.connect(&target).await.unwrap();

        stream.write_all(b"chunk-a").await.unwrap();
        stream.write_all(b"chunk-b").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut all = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, b"chunk-achunk-b");
    })
    .await;

    assert!(result.is_ok(), "grpc multi-write test timed out");
}

// --- Config 序列化测试 ---

#[test]
fn config_transport_h2_deserialize() {
    let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: my-vless
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      transport:
        type: h2
        path: "/tunnel"
        host: "example.com"
      tls:
        enabled: true
        sni: "example.com"
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
    let config: openworld::config::types::Config = serde_yml::from_str(yaml).unwrap();
    let vless = &config.outbounds[0].settings;
    let transport = vless.transport.as_ref().unwrap();
    assert_eq!(transport.transport_type, "h2");
    assert_eq!(transport.path.as_deref(), Some("/tunnel"));
    assert_eq!(transport.host.as_deref(), Some("example.com"));
}

#[test]
fn config_transport_grpc_deserialize() {
    let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: my-vless
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      transport:
        type: grpc
        service_name: "myService"
      tls:
        enabled: true
        sni: "example.com"
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
    let config: openworld::config::types::Config = serde_yml::from_str(yaml).unwrap();
    let vless = &config.outbounds[0].settings;
    let transport = vless.transport.as_ref().unwrap();
    assert_eq!(transport.transport_type, "grpc");
    assert_eq!(transport.service_name.as_deref(), Some("myService"));
}
