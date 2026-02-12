/// AnyTLS 传输层 — 基于多路复用的抗审查 TLS 传输。
///
/// AnyTLS 的核心思路：
/// 1. 与服务器建立看起来完全正常的 TLS 连接
/// 2. 在 TLS 层之上使用自定义分帧协议进行多路复用
/// 3. 通过 padding 和流量整形来对抗流量分析
///
/// ## 协议概述
/// - 底层: TLS 1.3 连接（标准 ClientHello，正常握手）
/// - 帧格式: [1 byte type][2 bytes length][payload]
///   - type 0x00: 数据帧
///   - type 0x01: padding 帧
///   - type 0x02: 打开新流
///   - type 0x03: 关闭流
///   - type 0x04: 密码验证
///
/// 配置示例:
/// ```yaml
/// transport:
///   type: anytls
///   password: "your-password"    # 认证密码
///   padding: true                # 启用 padding
/// ```

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::TlsConfig;

use super::StreamTransport;

/// AnyTLS 帧类型
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Data = 0x00,
    Padding = 0x01,
    Open = 0x02,
    Close = 0x03,
    Auth = 0x04,
}

impl TryFrom<u8> for FrameType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Padding),
            0x02 => Ok(Self::Open),
            0x03 => Ok(Self::Close),
            0x04 => Ok(Self::Auth),
            _ => anyhow::bail!("unknown anytls frame type: 0x{:02x}", value),
        }
    }
}

/// AnyTLS 传输层
pub struct AnyTlsTransport {
    server_addr: String,
    server_port: u16,
    password: String,
    padding: bool,
    dialer_config: Option<DialerConfig>,
    tls_config: Option<TlsConfig>,
}

impl AnyTlsTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        password: String,
        padding: bool,
        tls_config: Option<TlsConfig>,
        dialer_config: Option<DialerConfig>,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            password,
            padding,
            dialer_config,
            tls_config,
        }
    }

    /// 对密码进行 HMAC-SHA256 哈希（用于认证）
    fn compute_auth_token(&self) -> Vec<u8> {
        use sha2::Sha256;
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"anytls-auth-key")
            .expect("HMAC can take key of any size");
        mac.update(self.password.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// 构建 AnyTLS 帧
    fn encode_frame(frame_type: FrameType, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + payload.len());
        buf.push(frame_type as u8);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// 生成随机 padding 帧
    fn generate_padding_frame() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let len: usize = rng.gen_range(32..=512);
        let padding: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        Self::encode_frame(FrameType::Padding, &padding)
    }
}

#[async_trait]
impl StreamTransport for AnyTlsTransport {
    async fn connect(&self, addr: &Address) -> Result<ProxyStream> {
        // 1. 建立 TCP 连接
        let tcp = super::dial_tcp(&self.server_addr, self.server_port, &self.dialer_config).await?;

        // 2. TLS 握手
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // 使用默认 ALPN，看起来像正常 HTTPS 流量
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let server_name = self.tls_config
            .as_ref()
            .and_then(|c| c.sni.clone())
            .unwrap_or_else(|| self.server_addr.clone());

        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?;

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let mut tls_stream = connector.connect(server_name, tcp).await?;

        // 3. 发送认证帧
        let auth_token = self.compute_auth_token();
        let auth_frame = Self::encode_frame(FrameType::Auth, &auth_token);
        tls_stream.write_all(&auth_frame).await?;

        // 4. 可选：发送 padding 帧（对抗流量指纹）
        if self.padding {
            let padding_frame = Self::generate_padding_frame();
            tls_stream.write_all(&padding_frame).await?;
        }

        // 5. 发送 Open 帧，携带目标地址
        let target_str = match addr {
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Ip(ip) => ip.to_string(),
        };
        let open_frame = Self::encode_frame(FrameType::Open, target_str.as_bytes());
        tls_stream.write_all(&open_frame).await?;
        tls_stream.flush().await?;

        debug!(
            target = %target_str,
            server = %self.server_addr,
            padding = self.padding,
            "AnyTLS tunnel established"
        );

        // 6. 包装为 AnyTlsStream（处理帧协议）
        Ok(Box::new(AnyTlsStream {
            inner: Box::new(tls_stream),
            read_buf: BytesMut::new(),
        }))
    }
}

/// AnyTLS 流包装器
///
/// 在读取时自动跳过 padding 帧，只返回 Data 帧的数据。
/// 写入时自动封装为 Data 帧。
struct AnyTlsStream {
    inner: ProxyStream,
    read_buf: BytesMut,
}

impl AsyncRead for AnyTlsStream {
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

        // 从底层流读取帧头 (3 bytes: type + length)
        let mut header = [0u8; 3];
        let mut header_buf = tokio::io::ReadBuf::new(&mut header);
        match std::pin::Pin::new(&mut *self.inner).poll_read(cx, &mut header_buf) {
            Poll::Ready(Ok(())) => {
                if header_buf.filled().is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }

                let filled = header_buf.filled();
                if filled.len() < 3 {
                    // Short read — treat as data
                    buf.put_slice(filled);
                    return Poll::Ready(Ok(()));
                }

                let frame_type = filled[0];
                let frame_len = u16::from_be_bytes([filled[1], filled[2]]) as usize;

                match frame_type {
                    0x00 => {
                        // Data frame — read payload into buf
                        if frame_len == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        // For simplicity, put remaining data back
                        if frame_len <= buf.remaining() {
                            // Read directly into output buffer
                            let mut payload_buf = tokio::io::ReadBuf::new(
                                &mut buf.initialize_unfilled()[..frame_len]
                            );
                            match std::pin::Pin::new(&mut *self.inner).poll_read(cx, &mut payload_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = payload_buf.filled().len();
                                    buf.advance(n);
                                    Poll::Ready(Ok(()))
                                }
                                other => other,
                            }
                        } else {
                            // Buffer too small — partial read
                            let take = buf.remaining();
                            let mut payload_buf = tokio::io::ReadBuf::new(
                                &mut buf.initialize_unfilled()[..take]
                            );
                            match std::pin::Pin::new(&mut *self.inner).poll_read(cx, &mut payload_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = payload_buf.filled().len();
                                    buf.advance(n);
                                    Poll::Ready(Ok(()))
                                }
                                other => other,
                            }
                        }
                    }
                    0x01 => {
                        // Padding frame — skip and retry
                        // TODO: properly skip `frame_len` bytes
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    _ => {
                        // Unknown/control frame, skip
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // 封装为 Data 帧
        let frame = AnyTlsTransport::encode_frame(FrameType::Data, buf);
        match std::pin::Pin::new(&mut *self.inner).poll_write(cx, &frame) {
            std::task::Poll::Ready(Ok(n)) => {
                // 返回原始数据长度，而非帧长度
                if n >= 3 {
                    std::task::Poll::Ready(Ok(std::cmp::min(n - 3, buf.len())))
                } else {
                    std::task::Poll::Ready(Ok(0))
                }
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encoding() {
        let frame = AnyTlsTransport::encode_frame(FrameType::Data, b"hello");
        assert_eq!(frame[0], 0x00); // Data type
        assert_eq!(u16::from_be_bytes([frame[1], frame[2]]), 5);
        assert_eq!(&frame[3..], b"hello");
    }

    #[test]
    fn frame_type_conversion() {
        assert_eq!(FrameType::try_from(0x00).unwrap(), FrameType::Data);
        assert_eq!(FrameType::try_from(0x01).unwrap(), FrameType::Padding);
        assert_eq!(FrameType::try_from(0x04).unwrap(), FrameType::Auth);
        assert!(FrameType::try_from(0xFF).is_err());
    }

    #[test]
    fn padding_frame_generation() {
        let f1 = AnyTlsTransport::generate_padding_frame();
        let f2 = AnyTlsTransport::generate_padding_frame();
        assert_eq!(f1[0], 0x01); // Padding type
        assert_eq!(f2[0], 0x01);
        let len1 = u16::from_be_bytes([f1[1], f1[2]]) as usize;
        let len2 = u16::from_be_bytes([f2[1], f2[2]]) as usize;
        assert!(len1 >= 32 && len1 <= 512);
        assert!(len2 >= 32 && len2 <= 512);
    }

    #[test]
    fn auth_token_deterministic() {
        let transport = AnyTlsTransport::new(
            "test.com".to_string(),
            443,
            "password123".to_string(),
            false,
            None,
            None,
        );
        let t1 = transport.compute_auth_token();
        let t2 = transport.compute_auth_token();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32); // SHA-256 output
    }

    #[test]
    fn transport_creation() {
        let transport = AnyTlsTransport::new(
            "server.example.com".to_string(),
            443,
            "my-password".to_string(),
            true,
            None,
            None,
        );
        assert_eq!(transport.server_addr, "server.example.com");
        assert_eq!(transport.server_port, 443);
        assert!(transport.padding);
    }
}
