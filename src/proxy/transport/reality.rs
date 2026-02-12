use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::TlsConfig;
use crate::proxy::outbound::vless::reality;

use super::StreamTransport;

/// Reality 传输
///
/// 每次 connect 重新生成密钥对和 session_id。
pub struct RealityTransport {
    server_addr: String,
    server_port: u16,
    reality_config: reality::RealityConfig,
    sni: String,
    dialer_config: Option<DialerConfig>,
}

impl RealityTransport {
    pub fn new(server_addr: String, server_port: u16, config: &TlsConfig, dialer_config: Option<DialerConfig>) -> Result<Self> {
        let public_key_str = config
            .public_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("reality requires public_key"))?;
        let server_public_key = reality::parse_public_key(public_key_str)?;

        let short_id_str = config.short_id.as_deref().unwrap_or("");
        let short_id = if short_id_str.is_empty() {
            vec![]
        } else {
            reality::parse_hex(short_id_str)?
        };

        let server_name = config
            .server_name
            .clone()
            .or_else(|| config.sni.clone())
            .unwrap_or_else(|| server_addr.clone());

        let sni = config
            .sni
            .clone()
            .or_else(|| config.server_name.clone())
            .unwrap_or_else(|| server_addr.clone());

        Ok(Self {
            server_addr,
            server_port,
            reality_config: reality::RealityConfig {
                server_public_key,
                short_id,
                server_name,
            },
            sni,
            dialer_config,
        })
    }

    /// 使用自定义根证书构建（供测试使用）
    pub fn new_with_roots(
        server_addr: String,
        server_port: u16,
        reality_config: reality::RealityConfig,
        sni: String,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            reality_config,
            sni,
            dialer_config: None,
        }
    }
}

#[async_trait]
impl StreamTransport for RealityTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let tcp = super::dial_tcp(&self.server_addr, self.server_port, &self.dialer_config).await?;

        let (tls_config, handshake_ctx) = reality::build_reality_config(&self.reality_config)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.clone())?;
        let tls_stream = handshake_ctx
            .scope(|| connector.connect(server_name, tcp))
            .await?;

        debug!(sni = self.sni, "Reality handshake completed");
        Ok(Box::new(tls_stream))
    }
}
