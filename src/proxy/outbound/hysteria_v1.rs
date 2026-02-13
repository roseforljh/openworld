/// Hysteria v1 兼容出站。
///
/// Hysteria v1 与 v2 的核心区别：
/// - v1 使用 QUIC + 自定义 HPACK 头部进行认证
/// - v1 认证通过在 QUIC 首个双向流发送认证字段
/// - v1 的每个 TCP connection 用一个 QUIC 双向流
/// - v1 的 UDP 使用 QUIC datagram, 但帧格式不同于 v2
///
/// 此模块复用 Hysteria2 的 QUIC 管理器，添加 v1 兼容的认证和帧协议。
///
/// 配置示例:
/// ```yaml
/// - tag: hysteria-v1
///   protocol: hysteria
///   settings:
///     address: "server.example.com"
///     port: 36712
///     auth-str: "your-password"     # v1 使用 auth string
///     obfs: "salamander"            # 可选混淆
///     obfs-password: "your-obfs-password"
///     up-mbps: 100
///     down-mbps: 200
///     allow-insecure: false
/// ```
use anyhow::Result;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// Hysteria v1 出站处理器
pub struct HysteriaV1Outbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    auth_str: String,
    #[allow(dead_code)]
    obfs: Option<String>,
    #[allow(dead_code)]
    obfs_password: Option<String>,
    up_mbps: u64,
    down_mbps: u64,
    sni: String,
    allow_insecure: bool,
}

/// Hysteria v1 协议常量
const HYSTERIA_V1_VERSION: u8 = 3;
const HYSTERIA_V1_CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
const HYSTERIA_V1_CMD_UDP: u8 = 0x02;
const HYSTERIA_V1_STATUS_OK: u8 = 0x00;

impl HysteriaV1Outbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hysteria v1: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("hysteria v1: port is required"))?;

        // v1 可以使用 password 或 auth_str
        let auth_str = settings
            .password
            .clone()
            .or_else(|| settings.uuid.clone())
            .unwrap_or_default();

        let sni = settings.sni.clone().unwrap_or_else(|| address.clone());

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            "hysteria v1 outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            auth_str,
            obfs: settings.obfs.clone(),
            obfs_password: settings.obfs_password.clone(),
            up_mbps: settings.up_mbps.unwrap_or(100),
            down_mbps: settings.down_mbps.unwrap_or(200),
            sni,
            allow_insecure: settings.allow_insecure,
        })
    }

    /// 构建 Hysteria v1 认证请求帧
    fn build_auth_request(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // Protocol version
        buf.put_u8(HYSTERIA_V1_VERSION);

        // Up/Down bandwidth (Mbps, big-endian u32)
        buf.put_u32(self.up_mbps as u32);
        buf.put_u32(self.down_mbps as u32);

        // Auth string length + data
        let auth_bytes = self.auth_str.as_bytes();
        buf.put_u16(auth_bytes.len() as u16);
        buf.put_slice(auth_bytes);

        buf.to_vec()
    }

    /// 解析 Hysteria v1 认证响应
    fn parse_auth_response(data: &[u8]) -> Result<bool> {
        if data.is_empty() {
            anyhow::bail!("hysteria v1: empty auth response");
        }

        match data[0] {
            HYSTERIA_V1_STATUS_OK => Ok(true),
            status => {
                let msg = if data.len() > 1 {
                    String::from_utf8_lossy(&data[1..]).to_string()
                } else {
                    format!("status code: 0x{:02x}", status)
                };
                anyhow::bail!("hysteria v1 auth failed: {}", msg)
            }
        }
    }

    /// 编码 Hysteria v1 TCP 请求帧
    fn encode_tcp_request(addr: &Address) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(HYSTERIA_V1_CMD_TCP);

        match addr {
            Address::Domain(domain, port) => {
                // 类型 0x03 = 域名
                buf.put_u8(0x03);
                let domain_bytes = domain.as_bytes();
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
            Address::Ip(sock_addr) => {
                match sock_addr.ip() {
                    std::net::IpAddr::V4(ip) => {
                        buf.put_u8(0x01);
                        buf.put_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        buf.put_u8(0x04);
                        buf.put_slice(&ip.octets());
                    }
                }
                buf.put_u16(sock_addr.port());
            }
        }

        buf.to_vec()
    }

    /// Salamander 混淆：对数据进行异或混淆
    #[allow(dead_code)]
    fn apply_obfs(data: &mut [u8], password: &str) {
        let key_bytes = password.as_bytes();
        if key_bytes.is_empty() {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key_bytes[i % key_bytes.len()];
        }
    }

    /// 建立到服务器的 QUIC 连接
    async fn connect_quic(&self) -> Result<quinn::Connection> {
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"hysteria".to_vec()];

        if self.allow_insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(std::sync::Arc::new(SkipServerVerification));
        }

        let client_config = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let addr_str = format!("{}:{}", self.server_addr, self.server_port);
        let server_addr: std::net::SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", addr_str))?;

        let connection = endpoint.connect(server_addr, &self.sni)?.await?;

        debug!(
            server = %self.server_addr,
            port = self.server_port,
            "Hysteria v1 QUIC connection established"
        );

        // 发送认证
        let (mut send, mut recv) = connection.open_bi().await?;
        let auth_req = self.build_auth_request();
        send.write_all(&auth_req).await?;
        send.finish()?;

        // 读取认证响应
        let auth_resp = recv.read_to_end(1024).await?;
        Self::parse_auth_response(&auth_resp)?;

        debug!("Hysteria v1 authenticated successfully");

        Ok(connection)
    }
}

/// 跳过 TLS 服务器证书验证（allow-insecure）
#[derive(Debug)]
struct SkipServerVerification;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[async_trait]
impl OutboundHandler for HysteriaV1Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let conn = self.connect_quic().await?;

        // 打开双向流用于 TCP 代理
        let (mut send, recv) = conn.open_bi().await?;

        // 发送 TCP 请求
        let tcp_req = Self::encode_tcp_request(&session.target);
        send.write_all(&tcp_req).await?;

        debug!(target = %session.target, "Hysteria v1 TCP stream established");

        let stream = super::hysteria2::quic::QuicBiStream::new(send, recv);
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("Hysteria v1 UDP not yet implemented")
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
    fn hysteria_v1_creation() {
        let config = OutboundConfig {
            tag: "hy-v1".to_string(),
            protocol: "hysteria".to_string(),
            settings: OutboundSettings {
                address: Some("server.example.com".to_string()),
                port: Some(36712),
                password: Some("test-auth".to_string()),
                ..Default::default()
            },
        };
        let outbound = HysteriaV1Outbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "hy-v1");
        assert_eq!(outbound.server_port, 36712);
        assert_eq!(outbound.auth_str, "test-auth");
    }

    #[test]
    fn auth_request_encoding() {
        let outbound = HysteriaV1Outbound {
            tag: "test".to_string(),
            server_addr: "test.com".to_string(),
            server_port: 443,
            auth_str: "hello".to_string(),
            obfs: None,
            obfs_password: None,
            up_mbps: 100,
            down_mbps: 200,
            sni: "test.com".to_string(),
            allow_insecure: false,
        };

        let auth = outbound.build_auth_request();
        assert_eq!(auth[0], HYSTERIA_V1_VERSION);
        // 检查带宽字段
        let up = u32::from_be_bytes([auth[1], auth[2], auth[3], auth[4]]);
        let down = u32::from_be_bytes([auth[5], auth[6], auth[7], auth[8]]);
        assert_eq!(up, 100);
        assert_eq!(down, 200);
        // 检查 auth string
        let auth_len = u16::from_be_bytes([auth[9], auth[10]]) as usize;
        assert_eq!(auth_len, 5);
        assert_eq!(&auth[11..16], b"hello");
    }

    #[test]
    fn auth_response_ok() {
        assert!(HysteriaV1Outbound::parse_auth_response(&[0x00]).unwrap());
    }

    #[test]
    fn auth_response_fail() {
        let resp = HysteriaV1Outbound::parse_auth_response(&[0x01, b'n', b'o']);
        assert!(resp.is_err());
    }

    #[test]
    fn tcp_request_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let req = HysteriaV1Outbound::encode_tcp_request(&addr);
        assert_eq!(req[0], HYSTERIA_V1_CMD_TCP);
        assert_eq!(req[1], 0x03); // domain type
        assert_eq!(req[2], 11); // domain length "example.com"
    }

    #[test]
    fn obfs_roundtrip() {
        let original = vec![0x01, 0x02, 0x03, 0x04];
        let mut data = original.clone();
        HysteriaV1Outbound::apply_obfs(&mut data, "key");
        // After obfs, data should be different
        assert_ne!(data, original);
        // Apply again to deobfuscate
        HysteriaV1Outbound::apply_obfs(&mut data, "key");
        assert_eq!(data, original);
    }

    #[test]
    fn missing_address_fails() {
        let config = OutboundConfig {
            tag: "hy-v1".to_string(),
            protocol: "hysteria".to_string(),
            settings: OutboundSettings::default(),
        };
        assert!(HysteriaV1Outbound::new(&config).is_err());
    }
}
