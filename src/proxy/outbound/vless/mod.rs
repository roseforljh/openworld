pub mod protocol;
pub mod tls;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::ProxyStream;
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

pub struct VlessOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    uuid: uuid::Uuid,
    tls_config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
    sni: String,
}

impl VlessOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vless: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("vless: port is required"))?;
        let uuid_str = settings
            .uuid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vless: uuid is required"))?;
        let uuid = uuid_str.parse::<uuid::Uuid>()?;
        let sni = settings
            .sni
            .clone()
            .unwrap_or_else(|| address.clone());
        let allow_insecure = settings.allow_insecure;

        let tls_config = tls::build_tls_config(&sni, allow_insecure)?;

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            uuid,
            tls_config: std::sync::Arc::new(tls_config),
            sni,
        })
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        // 1. TCP 连接到服务器
        let server_addr = format!("{}:{}", self.server_addr, self.server_port);
        debug!(server = server_addr, "VLESS connecting to server");
        let tcp_stream = TcpStream::connect(&server_addr).await?;

        // 2. TLS 握手
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.clone())?;
        let tls_stream = connector.connect(server_name, tcp_stream).await?;

        debug!("VLESS TLS handshake completed");

        // 3. 发送 VLESS 请求头
        let mut stream: ProxyStream = Box::new(tls_stream);
        protocol::write_request(&mut stream, &self.uuid, &session.target).await?;

        // 4. 读取 VLESS 响应头
        protocol::read_response(&mut stream).await?;

        debug!(target = %session.target, "VLESS connection established");

        Ok(stream)
    }
}
