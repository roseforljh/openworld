use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use serde::Deserialize;

/// 代理目标地址
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Ip(addr) => addr.ip().to_string(),
            Address::Domain(domain, _) => domain.clone(),
        }
    }

    /// 编码为 VLESS 地址格式
    /// [AddrType: 1B] [Address: 变长]
    /// AddrType: 0x01=IPv4, 0x02=Domain, 0x03=IPv6
    pub fn encode_vless(&self, buf: &mut BytesMut) {
        match self {
            Address::Ip(SocketAddr::V4(addr)) => {
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Address::Ip(SocketAddr::V6(addr)) => {
                buf.put_u8(0x03);
                buf.put_slice(&addr.ip().octets());
            }
            Address::Domain(domain, _) => {
                buf.put_u8(0x02);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
            }
        }
    }

    /// 转换为 Hysteria2 地址字符串格式 "host:port"
    pub fn to_hysteria2_addr_string(&self) -> String {
        match self {
            Address::Ip(addr) => addr.to_string(),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }

    /// DNS 解析为 SocketAddr
    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            Address::Ip(addr) => Ok(*addr),
            Address::Domain(domain, port) => {
                let addr_str = format!("{}:{}", domain, port);
                let port = *port;
                let resolved = tokio::task::spawn_blocking(move || {
                    addr_str.to_socket_addrs()
                })
                .await??
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}:{}", domain, port))?;
                Ok(resolved)
            }
        }
    }

    /// 从 SOCKS5 地址格式解析
    /// atyp: 0x01=IPv4, 0x03=Domain, 0x04=IPv6
    pub fn from_socks5(atyp: u8, data: &[u8], port: u16) -> Result<Self> {
        match atyp {
            0x01 => {
                if data.len() < 4 {
                    anyhow::bail!("invalid IPv4 address length");
                }
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                Ok(Address::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            0x03 => {
                let domain = String::from_utf8(data.to_vec())?;
                Ok(Address::Domain(domain, port))
            }
            0x04 => {
                if data.len() < 16 {
                    anyhow::bail!("invalid IPv6 address length");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[..16]);
                let ip = Ipv6Addr::from(octets);
                Ok(Address::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
            }
            _ => anyhow::bail!("unsupported SOCKS5 address type: 0x{:02x}", atyp),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(addr) => write!(f, "{}", addr),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // 尝试解析为 SocketAddr
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Address::Ip(addr));
        }
        // 尝试解析为 host:port
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return Ok(Address::Ip(SocketAddr::new(ip, port)));
                }
                return Ok(Address::Domain(host.to_string(), port));
            }
        }
        Err(serde::de::Error::custom(format!("invalid address: {}", s)))
    }
}
