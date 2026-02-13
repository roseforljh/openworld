use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info};

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::{TlsConfig, TlsFragmentConfig};

use super::{ech, fingerprint, fragment::FragmentStream, StreamTransport};

/// TLS 传输
pub struct TlsTransport {
    server_addr: String,
    server_port: u16,
    /// Pre-built TLS config (None when ech_auto requires lazy initialization)
    static_tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Cached auto-resolved TLS config (populated on first connect when ech_auto)
    auto_tls_config: tokio::sync::OnceCell<Arc<rustls::ClientConfig>>,
    sni: String,
    dialer_config: Option<DialerConfig>,
    raw_tls_config: TlsConfig,
    /// TLS 分片配置（反审查）
    fragment_config: Option<TlsFragmentConfig>,
}

impl TlsTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        config: &TlsConfig,
        dialer_config: Option<DialerConfig>,
    ) -> Result<Self> {
        let sni = config.sni.clone().unwrap_or_else(|| server_addr.clone());

        let static_tls_config = if config.ech_auto {
            // Defer TLS config building to connect() for DNS-based ECH auto-fetch
            None
        } else {
            let alpn: Option<Vec<&str>> = config
                .alpn
                .as_ref()
                .map(|v| v.iter().map(|s| s.as_str()).collect());

            let fp = config
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
                fp,
                config.allow_insecure,
                alpn.as_deref(),
            )?;
            Some(Arc::new(tls_config))
        };

        Ok(Self {
            server_addr,
            server_port,
            static_tls_config,
            auto_tls_config: tokio::sync::OnceCell::new(),
            sni,
            dialer_config,
            fragment_config: config.fragment.clone(),
            raw_tls_config: config.clone(),
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
            static_tls_config: Some(Arc::new(tls_config)),
            auto_tls_config: tokio::sync::OnceCell::new(),
            sni,
            dialer_config: None,
            fragment_config: None,
            raw_tls_config: TlsConfig::default(),
        })
    }

    /// Get or build the TLS config, resolving ECH from DNS if needed
    async fn get_tls_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        if let Some(ref cfg) = self.static_tls_config {
            return Ok(cfg.clone());
        }

        self.auto_tls_config
            .get_or_try_init(|| async {
                let ech_settings =
                    ech::resolve_ech_settings(&self.raw_tls_config, &self.sni).await?;
                if ech_settings.is_enabled() {
                    info!(
                        server = %self.server_addr,
                        sni = %self.sni,
                        grease = ech_settings.grease,
                        has_config = ech_settings.config_list.is_some(),
                        "TLS transport will attempt ECH"
                    );
                }

                let alpn: Option<Vec<&str>> = self
                    .raw_tls_config
                    .alpn
                    .as_ref()
                    .map(|v| v.iter().map(|s| s.as_str()).collect());

                let fp = self
                    .raw_tls_config
                    .fingerprint
                    .as_deref()
                    .map(fingerprint::FingerprintType::from_str)
                    .unwrap_or(fingerprint::FingerprintType::None);

                let tls_config = ech::build_ech_tls_config(
                    &ech_settings,
                    fp,
                    self.raw_tls_config.allow_insecure,
                    alpn.as_deref(),
                )?;
                Ok(Arc::new(tls_config))
            })
            .await
            .cloned()
    }
}

#[async_trait]
impl StreamTransport for TlsTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let tcp = super::dial_tcp(
            &self.server_addr,
            self.server_port,
            &self.dialer_config,
            None,
        )
        .await?;

        let tls_config = self.get_tls_config().await?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.clone())?;

        // 如果配置了 TLS 分片，包装 TCP 流
        if let Some(ref frag_config) = self.fragment_config {
            debug!(
                sni = self.sni,
                min_len = frag_config.min_length,
                max_len = frag_config.max_length,
                "TLS fragment enabled"
            );
            let frag_stream = FragmentStream::new(tcp, frag_config.clone());
            let tls_stream = connector.connect(server_name, frag_stream).await?;
            debug!(sni = self.sni, "TLS handshake completed (fragmented)");
            Ok(Box::new(tls_stream))
        } else {
            let tls_stream = connector.connect(server_name, tcp).await?;
            debug!(sni = self.sni, "TLS handshake completed");
            Ok(Box::new(tls_stream))
        }
    }
}
