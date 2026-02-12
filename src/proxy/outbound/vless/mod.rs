pub mod protocol;
pub mod reality;
pub mod tls;
pub mod vision;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::mux::{MuxManager, MuxTransport, StreamConnector, XudpFrame, XudpMux};
use crate::proxy::transport::StreamTransport;
use crate::proxy::{OutboundHandler, Session};

/// VLESS flow 常量
pub const XRV: &str = "xtls-rprx-vision";

pub struct VlessOutbound {
    tag: String,
    server_addr: Address,
    uuid: uuid::Uuid,
    transport: Arc<dyn StreamTransport>,
    mux: Option<Arc<MuxManager>>,
    flow: Option<String>,
    xudp_mux: Arc<XudpMux>,
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

        // 构建有效的 TLS 配置
        let mut tls_config = settings.effective_tls();
        // 如果没有显式设置 tls，但有 security 字段，则启用 TLS
        if !tls_config.enabled && settings.security.is_some() {
            tls_config.enabled = true;
        }
        let ech_enabled = tls_config.ech_config.is_some() || tls_config.ech_auto || tls_config.ech_grease;
        if ech_enabled && !tls_config.enabled {
            tls_config.enabled = true;
            debug!("VLESS ECH is configured; force-enabling TLS transport");
        }
        // 如果 SNI 未设置，使用服务器地址
        if tls_config.sni.is_none() {
            tls_config.sni = Some(address.clone());
        }
        if ech_enabled && tls_config.ech_outer_sni.is_some() {
            tls_config.sni = tls_config.ech_outer_sni.clone();
            debug!(
                sni = tls_config.sni.as_deref().unwrap_or(""),
                "VLESS ECH enabled: using outer SNI for TLS handshake"
            );
        }
        // Vision flow 需要 ALPN
        if flow.as_deref() == Some(XRV) && tls_config.alpn.is_none() {
            tls_config.alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
        }

        let transport_config = settings.effective_transport();
        let transport: Arc<dyn StreamTransport> = crate::proxy::transport::build_transport_with_dialer(
            address,
            port,
            &transport_config,
            &tls_config,
            settings.dialer.clone(),
        )?
        .into();

        let server_addr = Address::Domain(address.clone(), port);
        let mux = settings.mux.clone().map(|mux_config| {
            let transport = transport.clone();
            let server_addr = server_addr.clone();
            let connector: StreamConnector = Arc::new(move || {
                let transport = transport.clone();
                let server_addr = server_addr.clone();
                Box::pin(async move { transport.connect(&server_addr).await })
            });
            Arc::new(MuxManager::new(mux_config, connector))
        });

        Ok(Self {
            tag: config.tag.clone(),
            server_addr,
            uuid,
            transport,
            mux,
            flow,
            xudp_mux: Arc::new(XudpMux::new()),
        })
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(server = %self.server_addr, "VLESS connecting to server");

        let mut stream = if let Some(mux) = &self.mux {
            mux.open_stream().await?
        } else {
            self.transport.connect(&self.server_addr).await?
        };

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

        debug!(target = %session.target, "VLESS UDP stream established (XUDP)");

        let session_id = self.xudp_mux.allocate_session_id();
        Ok(Box::new(VlessUdpTransport {
            stream: Mutex::new(stream),
            target: session.target.clone(),
            xudp_mux: self.xudp_mux.clone(),
            session_id,
            session_opened: Mutex::new(false),
        }))
    }
}

/// VLESS UDP 传输：通过 XUDP 协议在 TLS 流上多路复用 UDP 会话
struct VlessUdpTransport {
    stream: Mutex<ProxyStream>,
    target: Address,
    #[allow(dead_code)]
    xudp_mux: Arc<XudpMux>,
    session_id: u16,
    /// 是否已发送 NEW 帧
    session_opened: Mutex<bool>,
}

#[async_trait]
impl UdpTransport for VlessUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let mut opened = self.session_opened.lock().await;

        // 首次发送时先发 NEW 帧建立 XUDP 会话
        if !*opened {
            let new_frame = XudpFrame::new_session(self.session_id, packet.addr.clone());
            let encoded = new_frame.encode();
            protocol::write_udp_frame(&mut stream, &encoded).await?;
            *opened = true;
        }

        // 发送 DATA 帧
        let data_frame = XudpFrame::data(self.session_id, packet.addr, packet.data.to_vec());
        let encoded = data_frame.encode();
        protocol::write_udp_frame(&mut stream, &encoded).await
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut stream = self.stream.lock().await;
        loop {
            let data = protocol::read_udp_frame(&mut stream).await?;
            // 尝试解码 XUDP 帧
            match XudpFrame::decode(&data) {
                Ok((frame, _)) => {
                    match frame.frame_type {
                        0x02 => {
                            // DATA 帧
                            let addr = frame.address.unwrap_or_else(|| self.target.clone());
                            return Ok(UdpPacket {
                                addr,
                                data: bytes::Bytes::from(frame.payload),
                            });
                        }
                        0x03 => {
                            // CLOSE 帧
                            anyhow::bail!("XUDP session closed by remote");
                        }
                        0x04 => {
                            // KEEPALIVE — 忽略，继续读取
                            continue;
                        }
                        _ => {
                            // NEW 或其他 — 忽略
                            continue;
                        }
                    }
                }
                Err(_) => {
                    // 非 XUDP 帧，作为原始 UDP 数据返回（兼容旧服务端）
                    return Ok(UdpPacket {
                        addr: self.target.clone(),
                        data,
                    });
                }
            }
        }
    }
}
