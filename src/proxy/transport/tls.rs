use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::TlsConfig;

use super::{ech, fingerprint, StreamTransport};

/// TLS 传输
pub struct TlsTransport {
    server_addr: String,
    server_port: u16,
    tls_config: Arc<rustls::ClientConfig>,
    sni: String,
}

impl TlsTransport {
    pub fn new(server_addr: String, server_port: u16, config: &TlsConfig) -> Result<Self> {
        let sni = config.sni.clone().unwrap_or_else(|| server_addr.clone());

        let alpn: Option<Vec<&str>> = config
            .alpn
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect());

        let fingerprint = config
            .fingerprint
            .as_deref()
            .map(fingerprint::FingerprintType::from_str)
            .unwrap_or(fingerprint::FingerprintType::None);

        let ech_settings = ech::EchSettings {
            config_list: config
                .ech_config
                .as_deref()
                .map(ech::parse_ech_config_base64)
                .transpose()?,
            grease: config.ech_grease,
            outer_sni: config.ech_outer_sni.clone(),
        };

        let tls_config = ech::build_ech_tls_config(
            &ech_settings,
            fingerprint,
            config.allow_insecure,
            alpn.as_deref(),
        )?;

        Ok(Self {
            server_addr,
            server_port,
            tls_config: Arc::new(tls_config),
            sni,
        })
    }

    /// 使用自定义根证书构建（供测试使用）
    pub fn new_with_roots(
        server_addr: String,
        server_port: u16,
        sni: String,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
        alpn: Option<&[&str]>,
    ) -> Result<Self> {
        let tls_config = crate::common::tls::build_tls_config_with_roots(roots, alpn)?;
        Ok(Self {
            server_addr,
            server_port,
            tls_config: Arc::new(tls_config),
            sni,
        })
    }
}

#[async_trait]
impl StreamTransport for TlsTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let addr = format!("{}:{}", self.server_addr, self.server_port);
        let tcp = TcpStream::connect(&addr).await?;

        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.clone())?;
        let tls_stream = connector.connect(server_name, tcp).await?;

        debug!(sni = self.sni, "TLS handshake completed");
        Ok(Box::new(tls_stream))
    }
}
