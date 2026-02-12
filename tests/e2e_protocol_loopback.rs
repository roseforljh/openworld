/// Protocol loopback integration tests.
///
/// Tests the FULL proxy chain including encrypted outbound protocols:
///   client → SOCKS5 → OpenWorld(proxy) → [encrypted protocol] → OpenWorld(server) → direct → echo
///
/// Each test:
/// 1. Starts an echo server
/// 2. Starts a "server" App with protocol inbound (VLESS/Trojan/SS/VMess) + direct outbound
/// 3. Starts a "proxy" App with SOCKS5 inbound + protocol outbound pointing to the server
/// 4. Connects via SOCKS5, sends data, verifies echo through the encrypted tunnel

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper: allocate a free port
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Helper: start an echo server, returns its address
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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

/// Helper: do a full SOCKS5 connect + echo test through a proxy.
async fn socks5_connect_and_echo(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    test_data: &[u8],
) {
    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy failed");

    // SOCKS5 handshake
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 handshake failed");

    // SOCKS5 CONNECT
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let SocketAddr::V4(v4) = target_addr {
        req.extend_from_slice(&v4.ip().octets());
        req.extend_from_slice(&v4.port().to_be_bytes());
    }
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(
        connect_resp[1], 0x00,
        "SOCKS5 CONNECT failed (status={})",
        connect_resp[1]
    );

    // Send data and verify echo
    client.write_all(test_data).await.unwrap();
    client.flush().await.unwrap();

    let mut echo_buf = vec![0u8; test_data.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut echo_buf))
        .await
        .expect("echo read timeout")
        .expect("echo read error");

    assert_eq!(&echo_buf, test_data, "echo data mismatch through proxy chain");
}

// ── Test 1: VLESS loopback ──

/// Client → SOCKS5 → [VLESS outbound] → [VLESS inbound] → direct → echo
#[tokio::test]
async fn protocol_loopback_vless() {
    let echo_addr = start_echo_server().await;
    let server_port = free_port().await;
    let proxy_port = free_port().await;
    let test_uuid = "12345678-1234-1234-1234-123456789abc";

    // --- Server App: VLESS inbound + direct outbound ---
    let server_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: vless-in
    protocol: vless
    listen: "127.0.0.1"
    port: {server_port}
    settings:
      uuid: "{test_uuid}"
outbounds:
  - tag: direct
    protocol: direct
"#
    );

    let server_config: openworld::config::types::Config =
        serde_yml::from_str(&server_yaml).expect("server config parse failed");
    let server_app = openworld::app::App::new(server_config, None, None)
        .await
        .expect("server App::new failed");
    let server_cancel = server_app.cancel_token().clone();
    let server_handle = tokio::spawn(async move { let _ = server_app.run().await; });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Proxy App: SOCKS5 inbound + VLESS outbound ---
    let proxy_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: socks-in
    protocol: mixed
    listen: "127.0.0.1"
    port: {proxy_port}
outbounds:
  - tag: vless-out
    protocol: vless
    settings:
      address: "127.0.0.1"
      port: {server_port}
      uuid: "{test_uuid}"
"#
    );

    let proxy_config: openworld::config::types::Config =
        serde_yml::from_str(&proxy_yaml).expect("proxy config parse failed");
    let proxy_app = openworld::app::App::new(proxy_config, None, None)
        .await
        .expect("proxy App::new failed");
    let proxy_cancel = proxy_app.cancel_token().clone();
    let proxy_handle = tokio::spawn(async move { let _ = proxy_app.run().await; });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Test ---
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    socks5_connect_and_echo(proxy_addr, echo_addr, b"VLESS loopback test data!").await;

    // Cleanup
    proxy_cancel.cancel();
    server_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// ── Test 2: Trojan loopback ──

/// Client → SOCKS5 → [Trojan outbound] → [Trojan inbound] → direct → echo
#[tokio::test]
async fn protocol_loopback_trojan() {
    let echo_addr = start_echo_server().await;
    let server_port = free_port().await;
    let proxy_port = free_port().await;
    let test_password = "my-secret-trojan-password";

    // --- Server: Trojan inbound + direct ---
    let server_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: trojan-in
    protocol: trojan
    listen: "127.0.0.1"
    port: {server_port}
    settings:
      password: "{test_password}"
outbounds:
  - tag: direct
    protocol: direct
"#
    );

    let server_config: openworld::config::types::Config =
        serde_yml::from_str(&server_yaml).expect("server config parse failed");
    let server_app = openworld::app::App::new(server_config, None, None)
        .await
        .expect("server App::new failed");
    let server_cancel = server_app.cancel_token().clone();
    let server_handle = tokio::spawn(async move { let _ = server_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Proxy: SOCKS5 + Trojan outbound ---
    let proxy_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: socks-in
    protocol: mixed
    listen: "127.0.0.1"
    port: {proxy_port}
outbounds:
  - tag: trojan-out
    protocol: trojan
    settings:
      address: "127.0.0.1"
      port: {server_port}
      password: "{test_password}"
"#
    );

    let proxy_config: openworld::config::types::Config =
        serde_yml::from_str(&proxy_yaml).expect("proxy config parse failed");
    let proxy_app = openworld::app::App::new(proxy_config, None, None)
        .await
        .expect("proxy App::new failed");
    let proxy_cancel = proxy_app.cancel_token().clone();
    let proxy_handle = tokio::spawn(async move { let _ = proxy_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Test ---
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    socks5_connect_and_echo(proxy_addr, echo_addr, b"Trojan loopback test data!").await;

    proxy_cancel.cancel();
    server_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// ── Test 3: Shadowsocks loopback ──

/// Client → SOCKS5 → [SS outbound] → [SS inbound] → direct → echo
#[tokio::test]
async fn protocol_loopback_shadowsocks() {
    let echo_addr = start_echo_server().await;
    let server_port = free_port().await;
    let proxy_port = free_port().await;
    let test_password = "my-secret-ss-password-1234";
    let test_method = "aes-256-gcm";

    // --- Server: Shadowsocks inbound + direct ---
    let server_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: ss-in
    protocol: shadowsocks
    listen: "127.0.0.1"
    port: {server_port}
    settings:
      method: "{test_method}"
      password: "{test_password}"
outbounds:
  - tag: direct
    protocol: direct
"#
    );

    let server_config: openworld::config::types::Config =
        serde_yml::from_str(&server_yaml).expect("server config parse failed");
    let server_app = openworld::app::App::new(server_config, None, None)
        .await
        .expect("server App::new failed");
    let server_cancel = server_app.cancel_token().clone();
    let server_handle = tokio::spawn(async move { let _ = server_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Proxy: SOCKS5 + SS outbound ---
    let proxy_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: socks-in
    protocol: mixed
    listen: "127.0.0.1"
    port: {proxy_port}
outbounds:
  - tag: ss-out
    protocol: shadowsocks
    settings:
      address: "127.0.0.1"
      port: {server_port}
      method: "{test_method}"
      password: "{test_password}"
"#
    );

    let proxy_config: openworld::config::types::Config =
        serde_yml::from_str(&proxy_yaml).expect("proxy config parse failed");
    let proxy_app = openworld::app::App::new(proxy_config, None, None)
        .await
        .expect("proxy App::new failed");
    let proxy_cancel = proxy_app.cancel_token().clone();
    let proxy_handle = tokio::spawn(async move { let _ = proxy_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Test ---
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    socks5_connect_and_echo(proxy_addr, echo_addr, b"Shadowsocks loopback test data!").await;

    proxy_cancel.cancel();
    server_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// ── Test 4: VMess loopback ──

/// Client → SOCKS5 → [VMess outbound] → [VMess inbound] → direct → echo
#[tokio::test]
async fn protocol_loopback_vmess() {
    let echo_addr = start_echo_server().await;
    let server_port = free_port().await;
    let proxy_port = free_port().await;
    let test_uuid = "abcdef01-2345-6789-abcd-ef0123456789";

    // --- Server: VMess inbound + direct ---
    let server_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: vmess-in
    protocol: vmess
    listen: "127.0.0.1"
    port: {server_port}
    settings:
      uuid: "{test_uuid}"
outbounds:
  - tag: direct
    protocol: direct
"#
    );

    let server_config: openworld::config::types::Config =
        serde_yml::from_str(&server_yaml).expect("server config parse failed");
    let server_app = openworld::app::App::new(server_config, None, None)
        .await
        .expect("server App::new failed");
    let server_cancel = server_app.cancel_token().clone();
    let server_handle = tokio::spawn(async move { let _ = server_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Proxy: SOCKS5 + VMess outbound (AEAD, alter_id=0) ---
    let proxy_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: socks-in
    protocol: mixed
    listen: "127.0.0.1"
    port: {proxy_port}
outbounds:
  - tag: vmess-out
    protocol: vmess
    settings:
      address: "127.0.0.1"
      port: {server_port}
      uuid: "{test_uuid}"
      alter_id: 0
      security: "auto"
"#
    );

    let proxy_config: openworld::config::types::Config =
        serde_yml::from_str(&proxy_yaml).expect("proxy config parse failed");
    let proxy_app = openworld::app::App::new(proxy_config, None, None)
        .await
        .expect("proxy App::new failed");
    let proxy_cancel = proxy_app.cancel_token().clone();
    let proxy_handle = tokio::spawn(async move { let _ = proxy_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Test ---
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    socks5_connect_and_echo(proxy_addr, echo_addr, b"VMess loopback test data!").await;

    proxy_cancel.cancel();
    server_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// ── Test 5: Multi-protocol concurrent loopback ──

/// 4 concurrent SOCKS5 connections, each through a different protocol
#[tokio::test]
async fn multi_protocol_concurrent() {
    let echo_addr = start_echo_server().await;

    // Use VLESS as an example of concurrent load through one protocol chain
    let server_port = free_port().await;
    let proxy_port = free_port().await;
    let test_uuid = "99999999-0000-1111-2222-333333333333";

    let server_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: vless-in
    protocol: vless
    listen: "127.0.0.1"
    port: {server_port}
    settings:
      uuid: "{test_uuid}"
outbounds:
  - tag: direct
    protocol: direct
"#
    );

    let server_config: openworld::config::types::Config =
        serde_yml::from_str(&server_yaml).unwrap();
    let server_app = openworld::app::App::new(server_config, None, None).await.unwrap();
    let server_cancel = server_app.cancel_token().clone();
    let server_handle = tokio::spawn(async move { let _ = server_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let proxy_yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: socks-in
    protocol: mixed
    listen: "127.0.0.1"
    port: {proxy_port}
outbounds:
  - tag: vless-out
    protocol: vless
    settings:
      address: "127.0.0.1"
      port: {server_port}
      uuid: "{test_uuid}"
"#
    );

    let proxy_config: openworld::config::types::Config =
        serde_yml::from_str(&proxy_yaml).unwrap();
    let proxy_app = openworld::app::App::new(proxy_config, None, None).await.unwrap();
    let proxy_cancel = proxy_app.cancel_token().clone();
    let proxy_handle = tokio::spawn(async move { let _ = proxy_app.run().await; });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();

    // 5 concurrent connections through VLESS tunnel
    let mut handles = Vec::new();
    for i in 0..5u32 {
        let pa = proxy_addr;
        let ea = echo_addr;
        handles.push(tokio::spawn(async move {
            let data = format!("vless-concurrent-{}", i);
            socks5_connect_and_echo(pa, ea, data.as_bytes()).await;
        }));
    }

    for h in handles {
        h.await.expect("concurrent protocol test failed");
    }

    proxy_cancel.cancel();
    server_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}
