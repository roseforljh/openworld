pub mod auth;
pub mod protocol;
pub mod quic;

use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::common::ProxyStream;
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

pub struct Hysteria2Outbound {
    tag: String,
    password: String,
    quic_manager: std::sync::Arc<tokio::sync::Mutex<quic::QuicManager>>,
}

impl Hysteria2Outbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hysteria2: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("hysteria2: port is required"))?;
        let password = settings
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hysteria2: password is required"))?;
        let sni = settings.sni.clone().unwrap_or_else(|| address.clone());
        let allow_insecure = settings.allow_insecure;

        let quic_manager = quic::QuicManager::new(
            address.clone(),
            port,
            sni.clone(),
            allow_insecure,
        )?;

        Ok(Self {
            tag: config.tag.clone(),
            password: password.clone(),
            quic_manager: std::sync::Arc::new(tokio::sync::Mutex::new(quic_manager)),
        })
    }
}

#[async_trait]
impl OutboundHandler for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        // 1. 获取 QUIC 连接（复用或新建）
        let quic_conn = {
            let mut manager = self.quic_manager.lock().await;
            manager.get_connection().await?
        };

        // 2. 认证（如果是新连接）
        auth::authenticate(&quic_conn, &self.password).await?;

        // 3. 打开双向流
        let (mut send, mut recv) = quic_conn.open_bi().await?;

        // 4. 发送 TCP 请求头
        let addr_str = session.target.to_hysteria2_addr_string();
        protocol::write_tcp_request(&mut send, &addr_str).await?;

        // 5. 读取 TCP 响应
        protocol::read_tcp_response(&mut recv).await?;

        debug!(target = %session.target, "Hysteria2 TCP stream established");

        // 6. 包装为 ProxyStream
        let stream = quic::QuicBiStream::new(send, recv);
        Ok(Box::new(stream))
    }
}
