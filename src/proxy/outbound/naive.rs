/// NaiveProxy 出站 — HTTP/2 CONNECT 代理
///
/// NaiveProxy 基于 Chromium 的 HTTP/2 CONNECT 隧道实现代理，
/// 通过 TLS + HTTP/2 建立隧道连接，支持 padding 混淆。
///
/// 配置示例:
/// ```yaml
/// - tag: naive
///   protocol: naive
///   settings:
///     address: "server.example.com"
///     port: 443
///     uuid: "username"         # 用户名
///     password: "password"     # 密码
/// ```

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use h2::client;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

pub struct NaiveOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    username: String,
    password: String,
    dialer_config: Option<DialerConfig>,
}

impl NaiveOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings.address.as_ref().ok_or_else(|| {
            anyhow::anyhow!("naive outbound '{}' missing 'address'", config.tag)
        })?;
        let port = settings.port.unwrap_or(443);
        let username = settings.uuid.as_deref().unwrap_or("").to_string();
        let password = settings.password.as_deref().unwrap_or("").to_string();

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            "naive outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            username,
            password,
            dialer_config: settings.dialer.clone(),
        })
    }
}

/// 生成 NaiveProxy padding (随机长度的乱序字符)
fn generate_padding() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let len: usize = rng.gen_range(16..=256);
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen_range(b'a'..=b'z')).collect();
    String::from_utf8(bytes).unwrap()
}

/// NaiveProxy 流包装器 — 通过 h2 SendStream/RecvStream 实现双向 I/O
struct NaiveH2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// 缓冲区，存储从 h2 接收到但尚未被 AsyncRead 消费的数据
    read_buf: bytes::BytesMut,
}

impl AsyncRead for NaiveH2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        // 先从缓冲区读取
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf.split_to(len));
            return Poll::Ready(Ok(()));
        }

        // 从 h2 RecvStream 轮询数据
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // 释放流控容量
                let len = data.len();
                let _ = self.recv.flow_control().release_capacity(len);
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let take = buf.remaining();
                    buf.put_slice(&data[..take]);
                    self.read_buf.extend_from_slice(&data[take..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => {
                // 流结束
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for NaiveH2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;

        // 检查 h2 发送容量
        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let len = std::cmp::min(capacity, buf.len());
                let data = Bytes::copy_from_slice(&buf[..len]);
                self.send
                    .send_data(data, false)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "h2 stream closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // h2 在 send_data 时已经刷新
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl OutboundHandler for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let target = match &session.target {
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Ip(addr) => addr.to_string(),
        };

        debug!(target = %target, server = %self.server_addr, "naive CONNECT proxy");

        let dialer = match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        };

        // 1. 建立 TCP 连接
        let tcp_stream = dialer
            .connect_host(&self.server_addr, self.server_port)
            .await?;

        // 2. TLS 握手 (ALPN: h2)
        let tls_connector = {
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            config.alpn_protocols = vec![b"h2".to_vec()];
            std::sync::Arc::new(config)
        };

        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(
            self.server_addr.clone(),
        )
        .map_err(|e| anyhow::anyhow!("invalid server name '{}': {}", self.server_addr, e))?;

        let tls_connector = tokio_rustls::TlsConnector::from(tls_connector);
        let tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

        // 3. HTTP/2 客户端握手
        let (client, h2_conn) = client::handshake(tls_stream).await?;

        // 在后台驱动 HTTP/2 连接
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                debug!(error = %e, "naive h2 connection driver finished");
            }
        });

        let mut client = client.ready().await?;

        // 4. 发送 CONNECT 请求
        let mut req_builder = Request::builder()
            .method(http::Method::CONNECT)
            .uri(&target);

        // Proxy-Authorization
        if !self.username.is_empty() {
            let cred = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.username, self.password));
            req_builder = req_builder.header("proxy-authorization", format!("Basic {}", cred));
        }

        // NaiveProxy padding header
        req_builder = req_builder.header("padding", generate_padding());

        let req = req_builder.body(()).map_err(|e| anyhow::anyhow!("build request: {}", e))?;

        let (resp, send_stream) = client.send_request(req, false)?;
        let resp = resp.await?;

        if resp.status() != http::StatusCode::OK {
            anyhow::bail!(
                "naive proxy CONNECT failed: {}",
                resp.status()
            );
        }

        let recv_stream = resp.into_body();

        debug!(target = %target, "naive proxy H2 CONNECT tunnel established");

        Ok(Box::new(NaiveH2Stream {
            send: send_stream,
            recv: recv_stream,
            read_buf: bytes::BytesMut::new(),
        }))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("NaiveProxy does not support UDP")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn naive_outbound_creation() {
        let config = OutboundConfig {
            tag: "naive-out".to_string(),
            protocol: "naive".to_string(),
            settings: OutboundSettings {
                address: Some("server.example.com".to_string()),
                port: Some(443),
                uuid: Some("user".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        };
        let outbound = NaiveOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "naive-out");
        assert_eq!(outbound.server_port, 443);
        assert_eq!(outbound.username, "user");
        assert_eq!(outbound.password, "pass");
    }

    #[test]
    fn naive_outbound_default_port() {
        let config = OutboundConfig {
            tag: "naive".to_string(),
            protocol: "naive".to_string(),
            settings: OutboundSettings {
                address: Some("server.example.com".to_string()),
                ..Default::default()
            },
        };
        let outbound = NaiveOutbound::new(&config).unwrap();
        assert_eq!(outbound.server_port, 443);
    }

    #[test]
    fn naive_outbound_missing_address() {
        let config = OutboundConfig {
            tag: "naive".to_string(),
            protocol: "naive".to_string(),
            settings: OutboundSettings::default(),
        };
        assert!(NaiveOutbound::new(&config).is_err());
    }

    #[test]
    fn padding_generation() {
        let p1 = generate_padding();
        let p2 = generate_padding();
        assert!(p1.len() >= 16 && p1.len() <= 256);
        assert!(p2.len() >= 16 && p2.len() <= 256);
        // 极大概率不同
        assert_ne!(p1, p2);
    }
}
