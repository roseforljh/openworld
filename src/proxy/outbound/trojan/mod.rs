pub mod protocol;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::mux::{MuxManager, MuxTransport, StreamConnector};
use crate::proxy::transport::StreamTransport;
use crate::proxy::{OutboundHandler, Session};

pub struct TrojanOutbound {
    tag: String,
    server_addr: Address,
    password_hash: String,
    transport: Arc<dyn StreamTransport>,
    mux: Option<Arc<MuxManager>>,
}

impl TrojanOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("trojan: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("trojan: port is required"))?;
        let password = settings
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("trojan: password is required"))?;

        let password_hash = protocol::password_hash(password);

        // 构建有效的 TLS 配置
        let mut tls_config = settings.effective_tls();
        // Trojan 默认使用 TLS
        if !tls_config.enabled && settings.security.is_none() {
            tls_config.enabled = true;
        }
        if !tls_config.enabled && settings.security.as_deref() == Some("tls") {
            tls_config.enabled = true;
        }
        let ech_enabled =
            tls_config.ech_config.is_some() || tls_config.ech_auto || tls_config.ech_grease;
        if ech_enabled && !tls_config.enabled {
            tls_config.enabled = true;
            debug!("Trojan ECH is configured; force-enabling TLS transport");
        }
        // 如果 SNI 未设置，使用服务器地址
        if tls_config.sni.is_none() {
            tls_config.sni = Some(address.clone());
        }
        if ech_enabled && tls_config.ech_outer_sni.is_some() {
            tls_config.sni = tls_config.ech_outer_sni.clone();
            debug!(
                sni = tls_config.sni.as_deref().unwrap_or(""),
                "Trojan ECH enabled: using outer SNI for TLS handshake"
            );
        }

        let transport_config = settings.effective_transport();
        let transport: Arc<dyn StreamTransport> =
            crate::proxy::transport::build_transport_with_dialer(
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
            password_hash,
            transport,
            mux,
        })
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(server = %self.server_addr, "Trojan connecting to server");

        let mut stream = if let Some(mux) = &self.mux {
            mux.open_stream().await?
        } else {
            self.transport.connect(&self.server_addr).await?
        };

        protocol::write_request(
            &mut stream,
            &self.password_hash,
            &session.target,
            protocol::CMD_CONNECT,
        )
        .await?;

        debug!(target = %session.target, "Trojan connection established");
        Ok(stream)
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        debug!(server = %self.server_addr, target = %session.target, "Trojan UDP connecting");

        let mut stream = self.transport.connect(&self.server_addr).await?;

        protocol::write_request(
            &mut stream,
            &self.password_hash,
            &session.target,
            protocol::CMD_UDP_ASSOCIATE,
        )
        .await?;

        debug!(target = %session.target, "Trojan UDP stream established");

        Ok(Box::new(TrojanUdpTransport {
            stream: Mutex::new(stream),
            target: session.target.clone(),
        }))
    }
}

/// Trojan UDP 传输：通过 TLS 流收发 UDP 帧
struct TrojanUdpTransport {
    stream: Mutex<ProxyStream>,
    #[allow(dead_code)]
    target: Address,
}

#[async_trait]
impl UdpTransport for TrojanUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let mut stream = self.stream.lock().await;
        protocol::write_udp_frame(&mut stream, &packet.addr, &packet.data).await
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut stream = self.stream.lock().await;
        let (addr, data) = protocol::read_udp_frame(&mut stream).await?;
        Ok(UdpPacket {
            addr,
            data: data.into(),
        })
    }
}
