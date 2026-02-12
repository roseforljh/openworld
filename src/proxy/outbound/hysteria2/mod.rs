pub mod auth;
pub mod protocol;
pub mod quic;

use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, warn};

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// 全局 session ID 计数器
static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);

pub struct Hysteria2Outbound {
    tag: String,
    password: String,
    up_mbps: u64,
    down_mbps: u64,
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
        let up_mbps = settings.up_mbps.unwrap_or(0);
        let down_mbps = settings.down_mbps.unwrap_or(0);

        if up_mbps > 0 {
            debug!(
                up_mbps = up_mbps,
                "Hysteria2 using Brutal congestion control with configured uplink bandwidth"
            );
        }

        let brutal_mbps = if up_mbps > 0 { Some(up_mbps) } else { None };
        let quic_manager =
            quic::QuicManager::with_brutal(address.clone(), port, sni.clone(), allow_insecure, brutal_mbps)?;

        Ok(Self {
            tag: config.tag.clone(),
            password: password.clone(),
            up_mbps,
            down_mbps,
            quic_manager: std::sync::Arc::new(tokio::sync::Mutex::new(quic_manager)),
        })
    }

    /// 获取已认证的 QUIC 连接
    async fn get_authenticated_connection(&self) -> Result<quinn::Connection> {
        let mut manager = self.quic_manager.lock().await;
        let (conn, is_new) = manager.get_connection().await?;

        if is_new || !manager.is_authenticated() {
            let down_bps = self.down_mbps.saturating_mul(125_000);
            debug!(
                up_mbps = self.up_mbps,
                down_mbps = self.down_mbps,
                down_bps = down_bps,
                "Hysteria2 authenticating with bandwidth hints"
            );
            auth::authenticate(&conn, &self.password, down_bps).await?;
            manager.mark_authenticated();
        }

        Ok(conn)
    }
}

#[async_trait]
impl OutboundHandler for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let quic_conn = self.get_authenticated_connection().await?;

        // 打开双向流
        let (mut send, mut recv) = quic_conn.open_bi().await?;

        // 发送 TCP 请求头
        let addr_str = session.target.to_hysteria2_addr_string();
        protocol::write_tcp_request(&mut send, &addr_str).await?;

        // 读取 TCP 响应
        protocol::read_tcp_response(&mut recv).await?;

        debug!(target = %session.target, "Hysteria2 TCP stream established");

        let stream = quic::QuicBiStream::new(send, recv);
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        let quic_conn = self.get_authenticated_connection().await?;
        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);

        debug!(session_id = session_id, "Hysteria2 UDP transport created");

        Ok(Box::new(Hysteria2UdpTransport {
            connection: quic_conn,
            session_id,
            packet_id: AtomicU16::new(0),
        }))
    }
}

/// Hysteria2 UDP 传输：通过 QUIC Datagram 收发
struct Hysteria2UdpTransport {
    connection: quinn::Connection,
    session_id: u32,
    packet_id: AtomicU16,
}

#[async_trait]
impl UdpTransport for Hysteria2UdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let addr_str = packet.addr.to_hysteria2_addr_string();
        let msg = protocol::encode_udp_message(self.session_id, pid, &addr_str, &packet.data);
        self.connection.send_datagram(Bytes::from(msg))?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        loop {
            let datagram = self.connection.read_datagram().await?;
            let (sid, _pid, addr_str, payload) = protocol::decode_udp_message(&datagram)?;

            // 过滤非本 session 的包
            if sid != self.session_id {
                continue;
            }

            // 解析地址 "host:port"
            let addr = parse_hysteria2_addr(&addr_str)?;

            return Ok(UdpPacket {
                addr,
                data: payload,
            });
        }
    }
}

/// 解析 Hysteria2 地址字符串 "host:port" 为 Address
fn parse_hysteria2_addr(s: &str) -> Result<Address> {
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok(Address::Ip(addr));
    }
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid hysteria2 address: {}", s))?;
    let port: u16 = port_str.parse()?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(Address::Ip(std::net::SocketAddr::new(ip, port)));
    }
    Ok(Address::Domain(host.to_string(), port))
}
