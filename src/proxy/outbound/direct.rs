use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::debug;

use crate::common::{
    Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream, UdpPacket, UdpTransport,
};
use crate::proxy::{OutboundHandler, Session};

use super::pool::ConnectionPool;

pub struct DirectOutbound {
    tag: String,
    dialer_config: Option<DialerConfig>,
    pool: Arc<ConnectionPool>,
}

impl DirectOutbound {
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            dialer_config: None,
            pool: Arc::new(ConnectionPool::with_defaults()),
        }
    }

    pub fn with_dialer(mut self, dialer_config: Option<DialerConfig>) -> Self {
        self.dialer_config = dialer_config;
        self
    }

    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }
}

#[async_trait]
impl OutboundHandler for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let addr = session.target.resolve().await?;

        debug!(target = %session.target, resolved = %addr, "direct connect");
        let dialer = match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        };
        let stream = dialer.connect(addr).await?;
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        debug!(local = %socket.local_addr()?, "direct UDP socket bound");
        Ok(Box::new(DirectUdpTransport {
            socket: Arc::new(socket),
        }))
    }
}

struct DirectUdpTransport {
    socket: Arc<UdpSocket>,
}

#[async_trait]
impl UdpTransport for DirectUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let addr = packet.addr.resolve().await?;
        self.socket.send_to(&packet.data, addr).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok(UdpPacket {
            addr: Address::Ip(from),
            data: Bytes::from(buf),
        })
    }
}
