#![allow(
    clippy::field_reassign_with_default,
    clippy::redundant_field_names,
    clippy::needless_return,
    clippy::useless_format,
    unused_variables
)]
/// End-to-end proxy usability tests.
///
/// Tests the full chain: client → SOCKS5 inbound → dispatcher → direct outbound → target.
/// Validates that OpenWorld can actually proxy real TCP connections.
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ── Test 1: SOCKS5 handshake + CONNECT via in-process proxy ──

/// Full SOCKS5 proxy integration test:
/// 1. Start a TCP echo server
/// 2. Start OpenWorld with mixed inbound + direct outbound
/// 3. Connect via SOCKS5, send data, verify echo
#[tokio::test]
async fn socks5_proxy_echo_e2e() {
    // === Step 1: Start echo server ===
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match echo_listener.accept().await {
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

    // === Step 2: Build minimal config and start App ===
    let yaml_config = format!(
        r#"
log:
  level: debug

inbounds:
  - tag: test-mixed
    protocol: mixed
    listen: "127.0.0.1"
    port: 0

outbounds:
  - tag: direct
    protocol: direct
"#
    );

    // Parse config directly from YAML string
    let _config: openworld::config::types::Config =
        serde_yml::from_str(&yaml_config).expect("config parse failed");

    // We need to pick a free port for inbound
    let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = inbound_listener.local_addr().unwrap();
    drop(inbound_listener); // Release so App can bind

    // Override port in config
    let yaml_with_port = format!(
        r#"
log:
  level: debug

inbounds:
  - tag: test-mixed
    protocol: mixed
    listen: "127.0.0.1"
    port: {}

outbounds:
  - tag: direct
    protocol: direct
"#,
        proxy_addr.port()
    );

    let config: openworld::config::types::Config =
        serde_yml::from_str(&yaml_with_port).expect("config parse failed");

    let app = openworld::app::App::new(config, None, None)
        .await
        .expect("App::new failed");

    let cancel = app.cancel_token().clone();

    // Run app in background
    let app_handle = tokio::spawn(async move {
        let _ = app.run().await;
    });

    // Give the proxy time to bind and start listening
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === Step 3: Connect through SOCKS5 proxy ===
    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy failed");

    // SOCKS5 handshake: no auth
    // Version 5, 1 method, no auth (0x00)
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 handshake failed");

    // SOCKS5 CONNECT to echo server
    // Version 5, CMD CONNECT (1), RSV 0, ATYP IPv4 (1), addr, port
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01]; // v5, connect, rsv, ipv4
    match echo_addr {
        SocketAddr::V4(v4) => {
            connect_req.extend_from_slice(&v4.ip().octets());
            connect_req.extend_from_slice(&v4.port().to_be_bytes());
        }
        _ => panic!("expected IPv4"),
    }
    client.write_all(&connect_req).await.unwrap();

    let mut connect_resp = [0u8; 10]; // v5 + status + rsv + atyp(1) + addr(4) + port(2)
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(
        connect_resp[0], 0x05,
        "SOCKS5 CONNECT response version mismatch"
    );
    assert_eq!(
        connect_resp[1], 0x00,
        "SOCKS5 CONNECT failed with status: {}",
        connect_resp[1]
    );

    // === Step 4: Send data through proxy and verify echo ===
    let test_data = b"Hello from OpenWorld e2e test!";
    client.write_all(test_data).await.unwrap();
    client.flush().await.unwrap();

    let mut echo_buf = vec![0u8; test_data.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo_buf))
        .await
        .expect("echo timeout")
        .expect("echo read error");

    assert_eq!(
        &echo_buf, test_data,
        "Echo data mismatch: proxy did not relay correctly"
    );

    // === Step 5: Cleanup ===
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), app_handle).await;
}

// ── Test 2: HTTP proxy via mixed inbound ──

#[tokio::test]
async fn http_proxy_e2e() {
    // Start a simple HTTP server
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match http_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    // Start proxy
    let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let yaml = format!(
        r#"
log:
  level: debug
inbounds:
  - tag: test-mixed
    protocol: mixed
    listen: "127.0.0.1"
    port: {}
outbounds:
  - tag: direct
    protocol: direct
"#,
        proxy_addr.port()
    );

    let config: openworld::config::types::Config = serde_yml::from_str(&yaml).unwrap();
    let app = openworld::app::App::new(config, None, None)
        .await
        .expect("App::new failed");

    let cancel = app.cancel_token().clone();
    let app_handle = tokio::spawn(async move {
        let _ = app.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect through HTTP CONNECT proxy
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Send HTTP CONNECT
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        http_addr.ip(),
        http_addr.port(),
        http_addr.ip(),
        http_addr.port()
    );
    client.write_all(connect.as_bytes()).await.unwrap();

    // Read CONNECT response
    let mut resp_buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut resp_buf))
        .await
        .expect("CONNECT response timeout")
        .expect("CONNECT read error");

    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_str.contains("200"),
        "HTTP CONNECT failed: {}",
        resp_str
    );

    // Now send HTTP request through the tunnel
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        http_addr.ip(),
        http_addr.port()
    );
    client.write_all(http_req.as_bytes()).await.unwrap();

    // Read HTTP response
    let mut body_buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut body_buf))
        .await
        .expect("HTTP response timeout")
        .expect("HTTP read error");

    let body = String::from_utf8_lossy(&body_buf[..n]);
    assert!(
        body.contains("Hello, World!"),
        "HTTP response body mismatch: {}",
        body
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), app_handle).await;
}

// ── Test 3: Multiple concurrent connections ──

#[tokio::test]
async fn concurrent_proxy_connections() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match echo_listener.accept().await {
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

    let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let yaml = format!(
        r#"
log:
  level: warn
inbounds:
  - tag: test-mixed
    protocol: mixed
    listen: "127.0.0.1"
    port: {}
outbounds:
  - tag: direct
    protocol: direct
"#,
        proxy_addr.port()
    );

    let config: openworld::config::types::Config = serde_yml::from_str(&yaml).unwrap();
    let app = openworld::app::App::new(config, None, None)
        .await
        .expect("App::new failed");

    let cancel = app.cancel_token().clone();
    let app_handle = tokio::spawn(async move {
        let _ = app.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Spawn 10 concurrent connections
    let mut handles = Vec::new();
    for i in 0..10u32 {
        let proxy = proxy_addr;
        let echo = echo_addr;
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy).await.unwrap();

            // SOCKS5 handshake
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);

            // CONNECT
            let mut req = vec![0x05, 0x01, 0x00, 0x01];
            if let SocketAddr::V4(v4) = echo {
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(&v4.port().to_be_bytes());
            }
            client.write_all(&req).await.unwrap();

            let mut connect_resp = [0u8; 10];
            client.read_exact(&mut connect_resp).await.unwrap();
            assert_eq!(connect_resp[1], 0x00);

            // Send unique data
            let data = format!("connection-{}-data", i);
            client.write_all(data.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; data.len()];
            tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();

            assert_eq!(String::from_utf8(buf).unwrap(), data);
        }));
    }

    // Wait for all connections to complete
    for handle in handles {
        handle.await.expect("concurrent connection failed");
    }

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), app_handle).await;
}

// ── Test 4: Relay performance / throughput sanity check ──

#[tokio::test]
async fn relay_throughput_sanity() {
    use openworld::proxy::relay::{relay_with_options, RelayOptions, RelayStats};

    // Create a large chunk of data for throughput testing
    let data_size = 1024 * 1024; // 1 MiB
    let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

    let (mut client_a, client_b) = tokio::io::duplex(64 * 1024);
    let (remote_a, mut remote_b) = tokio::io::duplex(64 * 1024);

    let stats = RelayStats::new();
    let stats_clone = stats.clone();

    let relay_handle = tokio::spawn(async move {
        relay_with_options(
            client_b,
            remote_a,
            RelayOptions {
                stats: Some(stats_clone),
                ..Default::default()
            },
        )
        .await
    });

    // Write 1 MiB from client side
    let data_clone = data.clone();
    let write_handle = tokio::spawn(async move {
        client_a.write_all(&data_clone).await.unwrap();
        client_a.shutdown().await.unwrap();
    });

    // Read 1 MiB on remote side
    let mut received = Vec::with_capacity(data_size);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = remote_b.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    remote_b.shutdown().await.unwrap();

    write_handle.await.unwrap();
    let (up, _down) = relay_handle.await.unwrap().unwrap();

    // Verify all data transferred correctly
    assert_eq!(received.len(), data_size, "data size mismatch");
    assert_eq!(received, data, "data content mismatch");
    assert_eq!(up, data_size as u64, "relay upload stats mismatch");
    assert_eq!(
        stats.upload(),
        data_size as u64,
        "stats upload tracking mismatch"
    );
}
