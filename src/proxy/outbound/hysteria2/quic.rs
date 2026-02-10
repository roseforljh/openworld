use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// QUIC 连接管理器
pub struct QuicManager {
    server_addr: String,
    server_port: u16,
    sni: String,
    allow_insecure: bool,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    authenticated: bool,
}

impl QuicManager {
    pub fn new(
        server_addr: String,
        server_port: u16,
        sni: String,
        allow_insecure: bool,
    ) -> Result<Self> {
        Ok(Self {
            server_addr,
            server_port,
            sni,
            allow_insecure,
            endpoint: None,
            connection: None,
            authenticated: false,
        })
    }

    /// 获取 QUIC 连接（复用已有连接或创建新连接）
    /// 返回 (connection, is_new) - is_new 表示是否为新建连接（需要认证）
    pub async fn get_connection(&mut self) -> Result<(quinn::Connection, bool)> {
        // 检查现有连接是否可用
        if let Some(ref conn) = self.connection {
            if conn.close_reason().is_none() {
                return Ok((conn.clone(), false));
            }
        }

        // 创建新连接，重置认证状态
        let conn = self.create_connection().await?;
        self.connection = Some(conn.clone());
        self.authenticated = false;
        Ok((conn, true))
    }

    /// 标记当前连接已认证
    pub fn mark_authenticated(&mut self) {
        self.authenticated = true;
    }

    /// 当前连接是否已认证
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    async fn create_connection(&mut self) -> Result<quinn::Connection> {
        // 构建 TLS 配置
        let tls_config = build_quic_tls_config(&self.sni, self.allow_insecure)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));

        // 启用 datagram 支持（UDP 代理需要）
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport_config.datagram_receive_buffer_size(Some(1350 * 256));
        client_config.transport_config(Arc::new(transport_config));

        // 创建 endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        // 解析服务器地址
        let addr_str = format!("{}:{}", self.server_addr, self.server_port);
        let server_addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {}", addr_str))?;

        // 连接
        let conn = endpoint.connect(server_addr, &self.sni)?.await?;
        tracing::debug!(addr = %server_addr, "QUIC connection established");

        self.endpoint = Some(endpoint);
        Ok(conn)
    }
}

fn build_quic_tls_config(
    _sni: &str,
    allow_insecure: bool,
) -> Result<rustls::ClientConfig> {
    if allow_insecure {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        Ok(config)
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(config)
    }
}

/// 跳过证书验证
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// 将 QUIC 双向流包装为 AsyncRead + AsyncWrite
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
