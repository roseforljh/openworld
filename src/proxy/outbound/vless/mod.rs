pub mod protocol;
pub mod reality;
pub mod tls;
pub mod vision;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// VLESS flow 常量
pub const XRV: &str = "xtls-rprx-vision";

/// TLS 安全模式
#[derive(Debug, Clone)]
enum SecurityMode {
    Tls { config: Arc<rustls::ClientConfig>, sni: String },
    Reality { reality_config: reality::RealityConfig, sni: String },
}

pub struct VlessOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    uuid: uuid::Uuid,
    security: SecurityMode,
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

        let security_str = settings.security.as_deref().unwrap_or("tls");
        let security = match security_str {
            "reality" => {
                let public_key_str = settings
                    .public_key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("vless: reality requires public_key"))?;
                let server_public_key = reality::parse_public_key(public_key_str)?;

                let short_id_str = settings.short_id.as_deref().unwrap_or("");
                let short_id = if short_id_str.is_empty() {
                    vec![]
                } else {
                    reality::parse_hex(short_id_str)?
                };

                let server_name = settings
                    .server_name
                    .clone()
                    .or_else(|| settings.sni.clone())
                    .unwrap_or_else(|| address.clone());

                let sni = settings
                    .sni
                    .clone()
                    .or_else(|| settings.server_name.clone())
                    .unwrap_or_else(|| address.clone());

                SecurityMode::Reality {
                    reality_config: reality::RealityConfig {
                        server_public_key,
                        short_id,
                        server_name,
                    },
                    sni,
                }
            }
            "tls" | _ => {
                let sni = settings
                    .sni
                    .clone()
                    .unwrap_or_else(|| address.clone());
                let allow_insecure = settings.allow_insecure;
                let with_alpn = flow.as_deref() == Some(XRV);
                let tls_config = tls::build_tls_config(&sni, allow_insecure, with_alpn)?;

                SecurityMode::Tls {
                    config: Arc::new(tls_config),
                    sni,
                }
            }
        };

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            uuid,
            security,
            flow,
        })
    }

    /// 建立 TLS 连接（TCP + TLS 握手），复用于 TCP 和 UDP
    async fn establish_tls(&self) -> Result<ProxyStream> {
        let server_addr = format!("{}:{}", self.server_addr, self.server_port);
        let tcp_stream = TcpStream::connect(&server_addr).await?;

        match &self.security {
            SecurityMode::Tls { config, sni } => {
                let connector = tokio_rustls::TlsConnector::from(config.clone());
                let server_name = rustls::pki_types::ServerName::try_from(sni.clone())?;
                let tls_stream = connector.connect(server_name, tcp_stream).await?;
                debug!("VLESS TLS handshake completed");
                Ok(Box::new(tls_stream))
            }
            SecurityMode::Reality { reality_config, sni } => {
                let (tls_config, handshake_ctx) = reality::build_reality_config(reality_config)?;
                let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
                let server_name = rustls::pki_types::ServerName::try_from(sni.clone())?;
                let tls_stream = handshake_ctx
                    .scope(|| connector.connect(server_name, tcp_stream))
                    .await?;
                debug!("VLESS Reality handshake completed");
                Ok(Box::new(tls_stream))
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let server_addr = format!("{}:{}", self.server_addr, self.server_port);
        debug!(server = server_addr, "VLESS connecting to server");

        let mut stream = self.establish_tls().await?;

        // 发送 VLESS 请求头（TCP command）
        protocol::write_request(
            &mut stream,
            &self.uuid,
            &session.target,
            self.flow.as_deref(),
            protocol::CMD_TCP,
        )
        .await?;

        // 读取 VLESS 响应头
        protocol::read_response(&mut stream).await?;

        debug!(target = %session.target, "VLESS connection established");

        // 如果启用 Vision flow，包装为 VisionStream
        if self.flow.as_deref() == Some(XRV) {
            let vision_stream = vision::VisionStream::new(stream, self.uuid);
            Ok(Box::new(vision_stream))
        } else {
            Ok(stream)
        }
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let server_addr = format!("{}:{}", self.server_addr, self.server_port);
        debug!(server = server_addr, target = %session.target, "VLESS UDP connecting");

        let mut stream = self.establish_tls().await?;

        // 发送 VLESS 请求头（UDP command，不支持 Vision flow）
        protocol::write_request(
            &mut stream,
            &self.uuid,
            &session.target,
            None,
            protocol::CMD_UDP,
        )
        .await?;

        // 读取 VLESS 响应头
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
