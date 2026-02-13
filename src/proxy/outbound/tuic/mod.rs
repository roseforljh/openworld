use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::outbound::hysteria2::quic::QuicBiStream;
use crate::proxy::{OutboundHandler, Session};

/// TUIC v5 协议常量
#[allow(dead_code)]
const TUIC_VERSION: u8 = 0x05;

/// TUIC 命令类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TuicCommand {
    Authenticate = 0x00,
    Connect = 0x01,
    Packet = 0x02,
    Dissociate = 0x03,
    Heartbeat = 0x04,
}

impl TuicCommand {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(TuicCommand::Authenticate),
            0x01 => Some(TuicCommand::Connect),
            0x02 => Some(TuicCommand::Packet),
            0x03 => Some(TuicCommand::Dissociate),
            0x04 => Some(TuicCommand::Heartbeat),
            _ => None,
        }
    }
}

/// TUIC 地址类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TuicAddrType {
    None = 0xFF,
    Domain = 0x00,
    Ipv4 = 0x01,
    Ipv6 = 0x02,
}

/// TUIC 认证帧
#[derive(Debug, Clone)]
pub struct AuthenticateFrame {
    pub uuid: [u8; 16],
    pub token: Vec<u8>,
}

impl AuthenticateFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + self.token.len());
        buf.push(TuicCommand::Authenticate as u8);
        buf.extend_from_slice(&self.uuid);
        buf.extend_from_slice(&self.token);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 17 {
            anyhow::bail!("TUIC auth frame too short");
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[1..17]);
        let token = data[17..].to_vec();
        Ok(Self { uuid, token })
    }
}

/// TUIC Connect 帧
#[derive(Debug, Clone)]
pub struct ConnectFrame {
    pub addr_type: TuicAddrType,
    pub address: String,
    pub port: u16,
}

impl ConnectFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TuicCommand::Connect as u8);
        match self.addr_type {
            TuicAddrType::Domain => {
                buf.push(TuicAddrType::Domain as u8);
                let domain_bytes = self.address.as_bytes();
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
            }
            TuicAddrType::Ipv4 => {
                buf.push(TuicAddrType::Ipv4 as u8);
                if let Ok(ip) = self.address.parse::<std::net::Ipv4Addr>() {
                    buf.extend_from_slice(&ip.octets());
                }
            }
            TuicAddrType::Ipv6 => {
                buf.push(TuicAddrType::Ipv6 as u8);
                if let Ok(ip) = self.address.parse::<std::net::Ipv6Addr>() {
                    buf.extend_from_slice(&ip.octets());
                }
            }
            _ => {}
        }
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn from_address(addr: &Address) -> Self {
        match addr {
            Address::Ip(sock) => {
                let (addr_type, address) = match sock.ip() {
                    std::net::IpAddr::V4(v4) => (TuicAddrType::Ipv4, v4.to_string()),
                    std::net::IpAddr::V6(v6) => (TuicAddrType::Ipv6, v6.to_string()),
                };
                ConnectFrame {
                    addr_type,
                    address,
                    port: sock.port(),
                }
            }
            Address::Domain(domain, port) => ConnectFrame {
                addr_type: TuicAddrType::Domain,
                address: domain.clone(),
                port: *port,
            },
        }
    }
}

/// TUIC Packet 帧 (UDP)
#[derive(Debug, Clone)]
pub struct PacketFrame {
    pub assoc_id: u16,
    pub frag_id: u8,
    pub frag_total: u8,
    pub size: u16,
    pub addr_type: TuicAddrType,
    pub address: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

impl PacketFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TuicCommand::Packet as u8);
        buf.extend_from_slice(&self.assoc_id.to_be_bytes());
        buf.push(self.frag_id);
        buf.push(self.frag_total);
        buf.extend_from_slice(&self.size.to_be_bytes());
        match self.addr_type {
            TuicAddrType::Domain => {
                buf.push(TuicAddrType::Domain as u8);
                let domain_bytes = self.address.as_bytes();
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
            }
            TuicAddrType::Ipv4 => {
                buf.push(TuicAddrType::Ipv4 as u8);
                if let Ok(ip) = self.address.parse::<std::net::Ipv4Addr>() {
                    buf.extend_from_slice(&ip.octets());
                }
            }
            TuicAddrType::Ipv6 => {
                buf.push(TuicAddrType::Ipv6 as u8);
                if let Ok(ip) = self.address.parse::<std::net::Ipv6Addr>() {
                    buf.extend_from_slice(&ip.octets());
                }
            }
            _ => {}
        }
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn new_single(assoc_id: u16, addr: &Address, payload: &[u8]) -> Self {
        let (addr_type, address, port) = match addr {
            Address::Ip(sock) => match sock.ip() {
                std::net::IpAddr::V4(v4) => (TuicAddrType::Ipv4, v4.to_string(), sock.port()),
                std::net::IpAddr::V6(v6) => (TuicAddrType::Ipv6, v6.to_string(), sock.port()),
            },
            Address::Domain(d, p) => (TuicAddrType::Domain, d.clone(), *p),
        };
        PacketFrame {
            assoc_id,
            frag_id: 0,
            frag_total: 1,
            size: payload.len() as u16,
            addr_type,
            address,
            port,
            payload: payload.to_vec(),
        }
    }
}

/// TUIC 连接管理器
pub struct TuicConnectionManager {
    server_addr: String,
    server_port: u16,
    sni: String,
    allow_insecure: bool,
    uuid: [u8; 16],
    password: String,
    congestion: CongestionControl,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl CongestionControl {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bbr" => CongestionControl::Bbr,
            "new_reno" | "newreno" => CongestionControl::NewReno,
            _ => CongestionControl::Cubic,
        }
    }
}

impl TuicConnectionManager {
    pub fn new(
        server_addr: String,
        server_port: u16,
        sni: String,
        allow_insecure: bool,
        uuid: [u8; 16],
        password: String,
        congestion: CongestionControl,
    ) -> Result<Self> {
        Ok(Self {
            server_addr,
            server_port,
            sni,
            allow_insecure,
            uuid,
            password,
            congestion,
            endpoint: None,
            connection: None,
            authenticated: false,
        })
    }

    pub async fn get_connection(&mut self) -> Result<(quinn::Connection, bool)> {
        if let Some(ref conn) = self.connection {
            if conn.close_reason().is_none() {
                return Ok((conn.clone(), false));
            }
        }
        let conn = self.create_connection().await?;
        self.connection = Some(conn.clone());
        self.authenticated = false;
        Ok((conn, true))
    }

    pub fn mark_authenticated(&mut self) {
        self.authenticated = true;
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    async fn create_connection(&mut self) -> Result<quinn::Connection> {
        let mut tls_config = crate::common::tls::build_tls_config(self.allow_insecure, None)?;
        tls_config.enable_early_data = true; // Enable 0-RTT
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport_config.datagram_receive_buffer_size(Some(1350 * 256));
        // 设置拥塞控制算法
        match self.congestion {
            CongestionControl::Bbr => {
                transport_config.congestion_controller_factory(
                    Arc::new(quinn::congestion::BbrConfig::default()),
                );
            }
            CongestionControl::NewReno => {
                transport_config.congestion_controller_factory(
                    Arc::new(quinn::congestion::NewRenoConfig::default()),
                );
            }
            CongestionControl::Cubic => {
                transport_config.congestion_controller_factory(
                    Arc::new(quinn::congestion::CubicConfig::default()),
                );
            }
        }
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse::<std::net::SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        let addr_str = format!("{}:{}", self.server_addr, self.server_port);
        let server_addr: std::net::SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {}", addr_str))?;

        let connecting = endpoint.connect(server_addr, &self.sni)?;

        // Try 0-RTT for faster connection establishment
        let conn = match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                debug!(addr = %server_addr, "TUIC QUIC 0-RTT connection initiated");
                tokio::spawn(async move {
                    let accepted = zero_rtt_accepted.await;
                    debug!(accepted = accepted, "TUIC QUIC 0-RTT acceptance result");
                });
                conn
            }
            Err(connecting) => {
                let conn = connecting.await?;
                debug!(addr = %server_addr, "TUIC QUIC 1-RTT connection established");
                conn
            }
        };

        self.endpoint = Some(endpoint);
        Ok(conn)
    }

    async fn authenticate(&mut self, conn: &quinn::Connection) -> Result<()> {
        let token = compute_tuic_token(&self.uuid, &self.password);
        let frame = AuthenticateFrame {
            uuid: self.uuid,
            token,
        };
        let mut send = conn.open_uni().await?;
        #[allow(unused_imports)]
        use tokio::io::AsyncWriteExt;
        send.write_all(&frame.encode()).await?;
        send.finish()?;
        debug!("TUIC authentication sent");
        self.authenticated = true;
        Ok(())
    }
}

/// 计算 TUIC token = HMAC-SHA256(password, uuid)
fn compute_tuic_token(uuid: &[u8; 16], password: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(password.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(uuid);
    mac.finalize().into_bytes().to_vec()
}

/// 解析 UUID 字符串为 16 字节
fn parse_uuid_bytes(uuid_str: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(uuid_str)?;
    Ok(*uuid.as_bytes())
}

static NEXT_ASSOC_ID: AtomicU32 = AtomicU32::new(1);

/// TUIC v5 出站处理器
pub struct TuicOutbound {
    tag: String,
    manager: Arc<tokio::sync::Mutex<TuicConnectionManager>>,
}

impl TuicOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tuic: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("tuic: port is required"))?;
        let uuid_str = settings
            .uuid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tuic: uuid is required"))?;
        let password = settings
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tuic: password is required"))?;
        let sni = settings.sni.clone().unwrap_or_else(|| address.clone());
        let allow_insecure = settings.allow_insecure;
        let congestion = settings
            .congestion_control
            .as_deref()
            .map(CongestionControl::from_str)
            .unwrap_or(CongestionControl::Cubic);

        let uuid = parse_uuid_bytes(uuid_str)?;
        let manager = TuicConnectionManager::new(
            address.clone(),
            port,
            sni,
            allow_insecure,
            uuid,
            password.clone(),
            congestion,
        )?;

        Ok(Self {
            tag: config.tag.clone(),
            manager: Arc::new(tokio::sync::Mutex::new(manager)),
        })
    }
}

#[async_trait]
impl OutboundHandler for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let mut manager = self.manager.lock().await;
        let (conn, is_new) = manager.get_connection().await?;
        if is_new || !manager.is_authenticated() {
            manager.authenticate(&conn).await?;
        }
        drop(manager);

        let (mut send, recv) = conn.open_bi().await?;
        let connect_frame = ConnectFrame::from_address(&session.target);
        #[allow(unused_imports)]
        use tokio::io::AsyncWriteExt;
        send.write_all(&connect_frame.encode()).await?;

        debug!(target = %session.target, "TUIC TCP stream established");
        Ok(Box::new(QuicBiStream::new(send, recv)))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        let mut manager = self.manager.lock().await;
        let (conn, is_new) = manager.get_connection().await?;
        if is_new || !manager.is_authenticated() {
            manager.authenticate(&conn).await?;
        }
        drop(manager);

        let assoc_id = NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed) as u16;
        debug!(assoc_id = assoc_id, "TUIC UDP transport created");

        Ok(Box::new(TuicUdpTransport {
            connection: conn,
            assoc_id,
        }))
    }
}

struct TuicUdpTransport {
    connection: quinn::Connection,
    assoc_id: u16,
}

#[async_trait]
impl UdpTransport for TuicUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let frame = PacketFrame::new_single(self.assoc_id, &packet.addr, &packet.data);
        self.connection
            .send_datagram(Bytes::from(frame.encode()))?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        loop {
            let datagram = self.connection.read_datagram().await?;
            if datagram.is_empty() {
                continue;
            }
            if datagram[0] != TuicCommand::Packet as u8 {
                continue;
            }
            if datagram.len() < 8 {
                continue;
            }
            let assoc_id = u16::from_be_bytes([datagram[1], datagram[2]]);
            if assoc_id != self.assoc_id {
                continue;
            }
            let _frag_id = datagram[3];
            let _frag_total = datagram[4];
            let size = u16::from_be_bytes([datagram[5], datagram[6]]) as usize;
            let addr_type = datagram[7];
            let (addr, payload_start) = match addr_type {
                0x00 => {
                    if datagram.len() < 9 {
                        continue;
                    }
                    let domain_len = datagram[8] as usize;
                    let domain_end = 9 + domain_len;
                    if datagram.len() < domain_end + 2 {
                        continue;
                    }
                    let domain = String::from_utf8_lossy(&datagram[9..domain_end]).to_string();
                    let port = u16::from_be_bytes([datagram[domain_end], datagram[domain_end + 1]]);
                    (Address::Domain(domain, port), domain_end + 2)
                }
                0x01 => {
                    if datagram.len() < 14 {
                        continue;
                    }
                    let ip = std::net::Ipv4Addr::new(
                        datagram[8], datagram[9], datagram[10], datagram[11],
                    );
                    let port = u16::from_be_bytes([datagram[12], datagram[13]]);
                    (
                        Address::Ip(std::net::SocketAddr::new(ip.into(), port)),
                        14,
                    )
                }
                0x02 => {
                    if datagram.len() < 26 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&datagram[8..24]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([datagram[24], datagram[25]]);
                    (
                        Address::Ip(std::net::SocketAddr::new(ip.into(), port)),
                        26,
                    )
                }
                _ => continue,
            };
            let payload_end = payload_start + size;
            if datagram.len() < payload_end {
                continue;
            }
            return Ok(UdpPacket {
                addr,
                data: Bytes::copy_from_slice(&datagram[payload_start..payload_end]),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuic_command_from_byte() {
        assert_eq!(TuicCommand::from_byte(0x00), Some(TuicCommand::Authenticate));
        assert_eq!(TuicCommand::from_byte(0x01), Some(TuicCommand::Connect));
        assert_eq!(TuicCommand::from_byte(0x02), Some(TuicCommand::Packet));
        assert_eq!(TuicCommand::from_byte(0x03), Some(TuicCommand::Dissociate));
        assert_eq!(TuicCommand::from_byte(0x04), Some(TuicCommand::Heartbeat));
        assert_eq!(TuicCommand::from_byte(0xFF), None);
    }

    #[test]
    fn authenticate_frame_encode_decode() {
        let uuid = [1u8; 16];
        let token = vec![0xAA, 0xBB, 0xCC];
        let frame = AuthenticateFrame {
            uuid,
            token: token.clone(),
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], TuicCommand::Authenticate as u8);
        let decoded = AuthenticateFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.token, token);
    }

    #[test]
    fn authenticate_frame_too_short() {
        assert!(AuthenticateFrame::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn connect_frame_domain() {
        let frame = ConnectFrame {
            addr_type: TuicAddrType::Domain,
            address: "example.com".to_string(),
            port: 443,
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], TuicCommand::Connect as u8);
        assert_eq!(encoded[1], TuicAddrType::Domain as u8);
        assert_eq!(encoded[2], 11); // "example.com".len()
    }

    #[test]
    fn connect_frame_ipv4() {
        let addr = Address::Ip("1.2.3.4:80".parse().unwrap());
        let frame = ConnectFrame::from_address(&addr);
        assert_eq!(frame.addr_type, TuicAddrType::Ipv4);
        assert_eq!(frame.port, 80);
        let encoded = frame.encode();
        assert_eq!(encoded[0], TuicCommand::Connect as u8);
    }

    #[test]
    fn connect_frame_ipv6() {
        let addr = Address::Ip("[::1]:53".parse().unwrap());
        let frame = ConnectFrame::from_address(&addr);
        assert_eq!(frame.addr_type, TuicAddrType::Ipv6);
        assert_eq!(frame.port, 53);
    }

    #[test]
    fn packet_frame_encode() {
        let addr = Address::Domain("dns.google".to_string(), 53);
        let frame = PacketFrame::new_single(1, &addr, b"query");
        let encoded = frame.encode();
        assert_eq!(encoded[0], TuicCommand::Packet as u8);
        assert_eq!(frame.frag_id, 0);
        assert_eq!(frame.frag_total, 1);
        assert_eq!(frame.size, 5);
    }

    #[test]
    fn congestion_control_from_str() {
        assert_eq!(CongestionControl::from_str("bbr"), CongestionControl::Bbr);
        assert_eq!(CongestionControl::from_str("BBR"), CongestionControl::Bbr);
        assert_eq!(CongestionControl::from_str("new_reno"), CongestionControl::NewReno);
        assert_eq!(CongestionControl::from_str("newreno"), CongestionControl::NewReno);
        assert_eq!(CongestionControl::from_str("cubic"), CongestionControl::Cubic);
        assert_eq!(CongestionControl::from_str("unknown"), CongestionControl::Cubic);
    }

    #[test]
    fn compute_token_deterministic() {
        let uuid = [0xAA; 16];
        let t1 = compute_tuic_token(&uuid, "password");
        let t2 = compute_tuic_token(&uuid, "password");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32); // SHA256
    }

    #[test]
    fn compute_token_different_passwords() {
        let uuid = [0xBB; 16];
        let t1 = compute_tuic_token(&uuid, "pass1");
        let t2 = compute_tuic_token(&uuid, "pass2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn parse_uuid_valid() {
        let uuid = parse_uuid_bytes("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(uuid.len(), 16);
    }

    #[test]
    fn parse_uuid_invalid() {
        assert!(parse_uuid_bytes("not-a-uuid").is_err());
    }

    #[test]
    fn tuic_version_is_5() {
        assert_eq!(TUIC_VERSION, 0x05);
    }
}
