use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::{TlsConfig, TransportConfig};

use super::{ech, fingerprint, StreamTransport};

/// HTTPUpgrade 传输
///
/// 使用标准 HTTP/1.1 Upgrade 机制将连接升级为裸 TCP 流。
/// 相比 WebSocket，它不进行帧封装，因此：
/// - 更低开销（无 WS 帧头）
/// - CDN 友好（大部分 CDN 支持 HTTP Upgrade）
/// - 兼容 Xray / sing-box / mihomo
///
/// 协议流程：
/// 1. 客户端发送 `GET /path HTTP/1.1` + `Connection: Upgrade` + `Upgrade: websocket`
/// 2. 服务器返回 `101 Switching Protocols`
/// 3. 之后双向裸流传输
pub struct HttpUpgradeTransport {
    server_addr: String,
    server_port: u16,
    path: String,
    host: Option<String>,
    headers: Option<std::collections::HashMap<String, String>>,
    tls_config: Option<TlsConfig>,
    dialer_config: Option<DialerConfig>,
}

impl HttpUpgradeTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        transport_config: &TransportConfig,
        tls_config: Option<TlsConfig>,
        dialer_config: Option<DialerConfig>,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            path: transport_config
                .path
                .clone()
                .unwrap_or_else(|| "/".to_string()),
            host: transport_config.host.clone(),
            headers: transport_config.headers.clone(),
            tls_config,
            dialer_config,
        }
    }
}

#[async_trait]
impl StreamTransport for HttpUpgradeTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let host = self.host.as_deref().unwrap_or(&self.server_addr);

        // 1. 建立底层 TCP 连接
        let tcp_stream =
            super::dial_tcp(&self.server_addr, self.server_port, &self.dialer_config, None).await?;

        // 2. 可选 TLS 层
        let use_tls = self.tls_config.as_ref().map_or(false, |c| c.enabled);
        let mut stream: ProxyStream = if use_tls {
            let tls_cfg = self
                .tls_config
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TLS enabled but tls_config missing"))?;
            let sni = tls_cfg.sni.as_deref().unwrap_or(&self.server_addr);
            let alpn: Option<Vec<&str>> = tls_cfg
                .alpn
                .as_ref()
                .map(|v| v.iter().map(|s| s.as_str()).collect());
            let fp = tls_cfg
                .fingerprint
                .as_deref()
                .map(fingerprint::FingerprintType::from_str)
                .unwrap_or(fingerprint::FingerprintType::None);
            let ech_settings = ech::resolve_ech_settings(tls_cfg, sni).await?;
            let rustls_config = ech::build_ech_tls_config(
                &ech_settings,
                fp,
                tls_cfg.allow_insecure,
                alpn.as_deref(),
            )?;
            let connector =
                tokio_rustls::TlsConnector::from(std::sync::Arc::new(rustls_config));
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
            let tls_stream = connector.connect(server_name, tcp_stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };

        // 3. 发送 HTTP/1.1 Upgrade 请求
        //
        // 使用 Sec-WebSocket-Key 和 Upgrade: websocket 头以兼容
        // 要求 WebSocket Upgrade 的 CDN（如 Cloudflare）
        let ws_key = generate_ws_key();
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {}\r\n",
            self.path, host, ws_key
        );

        // 添加自定义头
        if let Some(ref headers) = self.headers {
            for (key, value) in headers {
                request.push_str(&format!("{}: {}\r\n", key, value));
            }
        }

        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        // 4. 读取 101 响应（手动逐字节读取，避免 BufReader 的 Debug 要求）
        let status_line = read_http_line(&mut stream).await?;

        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("httpupgrade: invalid response: {}", status_line.trim()))?;

        if status_code != 101 {
            anyhow::bail!(
                "httpupgrade: expected 101 Switching Protocols, got {}: {}",
                status_code,
                status_line.trim()
            );
        }

        // 跳过响应头
        loop {
            let line = read_http_line(&mut stream).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        debug!(path = self.path, host = host, "HTTPUpgrade connection established");

        // 5. 返回裸流 — 不需要 WS 帧封装
        Ok(stream)
    }
}

/// 生成 WebSocket key（复用 tungstenite 的实现）
fn generate_ws_key() -> String {
    tokio_tungstenite::tungstenite::handshake::client::generate_key()
}

/// 逐字节读取一行 HTTP 响应（到 \n 为止）
async fn read_http_line(stream: &mut ProxyStream) -> Result<String> {
    let mut line = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if line.len() > 8192 {
            anyhow::bail!("httpupgrade: response line too long");
        }
    }
    Ok(String::from_utf8_lossy(&line).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::TransportConfig;
    use tokio::io::AsyncReadExt;

    #[test]
    fn httpupgrade_transport_creation() {
        let tc = TransportConfig {
            transport_type: "httpupgrade".to_string(),
            path: Some("/tunnel".to_string()),
            host: Some("cdn.example.com".to_string()),
            ..Default::default()
        };
        let transport = HttpUpgradeTransport::new(
            "1.2.3.4".to_string(),
            443,
            &tc,
            None,
            None,
        );
        assert_eq!(transport.path, "/tunnel");
        assert_eq!(transport.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(transport.server_port, 443);
    }

    #[test]
    fn httpupgrade_default_path() {
        let tc = TransportConfig::default();
        let transport = HttpUpgradeTransport::new(
            "1.2.3.4".to_string(),
            443,
            &tc,
            None,
            None,
        );
        assert_eq!(transport.path, "/");
    }

    #[test]
    fn ws_key_generation() {
        let key = generate_ws_key();
        assert!(key.len() > 20); // base64 of 16 bytes = 24 chars
        // Verify it's valid base64
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&key).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[tokio::test]
    async fn httpupgrade_connect_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let tc = TransportConfig {
            transport_type: "httpupgrade".to_string(),
            path: Some("/proxy".to_string()),
            ..Default::default()
        };
        let transport = HttpUpgradeTransport::new(
            "127.0.0.1".to_string(),
            port,
            &tc,
            None,
            None,
        );

        // 模拟 HTTP Upgrade 服务器
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);

            assert!(request.contains("GET /proxy HTTP/1.1"));
            assert!(request.contains("Connection: Upgrade"));
            assert!(request.contains("Upgrade: websocket"));
            assert!(request.contains("Sec-WebSocket-Key:"));

            // 回复 101
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

            // 发送测试数据（裸流）
            sock.write_all(b"HELLO_FROM_SERVER").await.unwrap();
        });

        let addr = Address::Domain("example.com".to_string(), 443);
        let mut stream = transport.connect(&addr).await.unwrap();

        // 读取裸流数据
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HELLO_FROM_SERVER");

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn httpupgrade_non_101_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let tc = TransportConfig {
            transport_type: "httpupgrade".to_string(),
            ..Default::default()
        };
        let transport = HttpUpgradeTransport::new(
            "127.0.0.1".to_string(),
            port,
            &tc,
            None,
            None,
        );

        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });

        let addr = Address::Domain("example.com".to_string(), 443);
        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected error"),
        };
        assert!(err_msg.contains("101"));

        handle.await.unwrap();
    }
}
