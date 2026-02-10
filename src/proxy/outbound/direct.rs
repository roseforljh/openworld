use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::proxy::{OutboundHandler, Session};

pub struct DirectOutbound {
    tag: String,
}

impl DirectOutbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl OutboundHandler for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let addr = session.target.resolve().await?;
        debug!(target = %session.target, resolved = %addr, "direct connect");
        let stream = TcpStream::connect(addr).await?;
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
