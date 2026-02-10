pub mod protocol;
pub mod reality;
pub mod tls;
pub mod vision;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// VLESS flow 常量
pub const XRV: &str = "xtls-rprx-vision";

pub struct VlessOutbound {
    tag: String,
    server_addr: Address,
    uuid: uuid::Uuid,
    transport: Box<dyn crate::proxy::transport::StreamTransport>,
    flow: Option<String>,
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

        let flow = settings.flow.clone();
        if let Some(ref f) = flow {
            if f != XRV {
                anyhow::bail!("vless: unsupported flow: {}", f);
            }
        }

        if settings.fingerprint.is_some() {
            tracing::warn!("vless: 'fingerprint' is configured but not yet implemented");
        }

        // 构建有效的 TLS 配置
        let mut tls_config = settings.effective_tls();
        // 如果没有显式设置 tls，但有 security 字段，则启用 TLS
        if !tls_config.enabled && settings.security.is_some() {
            tls_config.enabled = true;
        }
        // 如果 SNI 未设置，使用服务器地址
        if tls_config.sni.is_none() {
            tls_config.sni = Some(address.clone());
        }
        // Vision flow 需要 ALPN
        if flow.as_deref() == Some(XRV) && tls_config.alpn.is_none() {
            tls_config.alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
        }

        let transport_config = settings.effective_transport();
        let transport = crate::proxy::transport::build_transport(
            address,
            port,
            &transport_config,
            &tls_config,
        )?;

        let server_addr = Address::Domain(address.clone(), port);

        Ok(Self {
            tag: config.tag.clone(),
            server_addr,
            uuid,
            transport,
            flow,
        })
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(server = %self.server_addr, "VLESS connecting to server");

        let mut stream = self.transport.connect(&self.server_addr).await?;

        protocol::write_request(
            &mut stream,
            &self.uuid,
            &session.target,
            self.flow.as_deref(),
            protocol::CMD_TCP,
        )
        .await?;

        protocol::read_response(&mut stream).await?;

        debug!(target = %session.target, "VLESS connection established");

        if self.flow.as_deref() == Some(XRV) {
            let vision_stream = vision::VisionStream::new(stream, self.uuid);
            Ok(Box::new(vision_stream))
        } else {
            Ok(stream)
        }
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        debug!(server = %self.server_addr, target = %session.target, "VLESS UDP connecting");

        let mut stream = self.transport.connect(&self.server_addr).await?;

        protocol::write_request(
            &mut stream,
            &self.uuid,
            &session.target,
            None,
            protocol::CMD_UDP,
        )
        .await?;

        protocol::read_response(&mut stream).await?;

        debug!(target = %session.target, "VLESS UDP stream established");

        Ok(Box::new(VlessUdpTransport {
            stream: Mutex::new(stream),
            target: session.target.clone(),
        }))
    }
}

/// VLESS UDP 传输：通过 TLS 流收发 UDP 帧
struct VlessUdpTransport {
    stream: Mutex<ProxyStream>,
    target: Address,
}

#[async_trait]
impl UdpTransport for VlessUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let mut stream = self.stream.lock().await;
        protocol::write_udp_frame(&mut stream, &packet.data).await
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut stream = self.stream.lock().await;
        let data = protocol::read_udp_frame(&mut stream).await?;
        Ok(UdpPacket {
            addr: self.target.clone(),
            data,
        })
    }
}
