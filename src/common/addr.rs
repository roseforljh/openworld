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

    /// 编码为 SOCKS5 地址格式 [ATYP][ADDR][PORT]
    pub fn encode_socks5(&self, buf: &mut BytesMut) {
        match self {
            Address::Ip(SocketAddr::V4(addr)) => {
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::Ip(SocketAddr::V6(addr)) => {
                buf.put_u8(0x04);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::Domain(domain, port) => {
                buf.put_u8(0x03);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    /// 从 SOCKS5 UDP 数据报头解析地址
    /// 数据格式: [ATYP: 1B][ADDR: 变长][PORT: 2B]
    /// 返回 (Address, 消耗的字节数)
    pub fn parse_socks5_udp_addr(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            anyhow::bail!("empty data for SOCKS5 address parsing");
        }
        let atyp = data[0];
        match atyp {
            0x01 => {
                // IPv4: 1(atyp) + 4(ip) + 2(port) = 7
                if data.len() < 7 {
                    anyhow::bail!("insufficient data for IPv4 SOCKS5 address");
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Address::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
            }
            0x03 => {
                // Domain: 1(atyp) + 1(len) + N(domain) + 2(port)
                if data.len() < 2 {
                    anyhow::bail!("insufficient data for domain SOCKS5 address");
                }
                let domain_len = data[1] as usize;
                let total = 2 + domain_len + 2;
                if data.len() < total {
                    anyhow::bail!("insufficient data for domain SOCKS5 address");
                }
                let domain = String::from_utf8(data[2..2 + domain_len].to_vec())?;
                let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
                Ok((Address::Domain(domain, port), total))
            }
            0x04 => {
                // IPv6: 1(atyp) + 16(ip) + 2(port) = 19
                if data.len() < 19 {
                    anyhow::bail!("insufficient data for IPv6 SOCKS5 address");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Address::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 19))
            }
            _ => anyhow::bail!("unsupported SOCKS5 address type: 0x{:02x}", atyp),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_socks5_ipv4() {
        let addr = Address::from_socks5(0x01, &[127, 0, 0, 1], 8080).unwrap();
        assert_eq!(addr, Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)));
    }

    #[test]
    fn from_socks5_ipv6() {
        let data = [0u8; 16];
        let addr = Address::from_socks5(0x04, &data, 443).unwrap();
        assert_eq!(addr, Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443)));
    }

    #[test]
    fn from_socks5_domain() {
        let addr = Address::from_socks5(0x03, b"example.com", 443).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 443));
    }

    #[test]
    fn from_socks5_invalid_atyp() {
        assert!(Address::from_socks5(0xFF, &[], 80).is_err());
    }

    #[test]
    fn from_socks5_ipv4_too_short() {
        assert!(Address::from_socks5(0x01, &[127, 0, 0], 80).is_err());
    }

    #[test]
    fn from_socks5_ipv6_too_short() {
        assert!(Address::from_socks5(0x04, &[0u8; 10], 80).is_err());
    }

    #[test]
    fn encode_vless_ipv4() {
        let addr = Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
        let mut buf = BytesMut::new();
        addr.encode_vless(&mut buf);
        assert_eq!(&buf[..], &[0x01, 1, 2, 3, 4]);
    }

    #[test]
    fn encode_vless_ipv6() {
        let addr = Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443));
        let mut buf = BytesMut::new();
        addr.encode_vless(&mut buf);
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf.len(), 1 + 16);
    }

    #[test]
    fn encode_vless_domain() {
        let addr = Address::Domain("test.com".to_string(), 443);
        let mut buf = BytesMut::new();
        addr.encode_vless(&mut buf);
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[1], 8);
        assert_eq!(&buf[2..], b"test.com");
    }

    #[test]
    fn hysteria2_addr_string_ip() {
        let addr = Address::Ip("127.0.0.1:8080".parse().unwrap());
        assert_eq!(addr.to_hysteria2_addr_string(), "127.0.0.1:8080");
    }

    #[test]
    fn hysteria2_addr_string_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        assert_eq!(addr.to_hysteria2_addr_string(), "example.com:443");
    }

    #[test]
    fn port_and_host() {
        let ip_addr = Address::Ip("10.0.0.1:3000".parse().unwrap());
        assert_eq!(ip_addr.port(), 3000);
        assert_eq!(ip_addr.host(), "10.0.0.1");

        let domain_addr = Address::Domain("foo.bar".to_string(), 8443);
        assert_eq!(domain_addr.port(), 8443);
        assert_eq!(domain_addr.host(), "foo.bar");
    }

    #[test]
    fn display_format() {
        let addr = Address::Domain("example.com".to_string(), 443);
        assert_eq!(format!("{}", addr), "example.com:443");

        let addr = Address::Ip("1.2.3.4:80".parse().unwrap());
        assert_eq!(format!("{}", addr), "1.2.3.4:80");
    }

    #[test]
    fn encode_socks5_ipv4() {
        let addr = Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
        let mut buf = BytesMut::new();
        addr.encode_socks5(&mut buf);
        assert_eq!(&buf[..], &[0x01, 1, 2, 3, 4, 0x01, 0xBB]); // port 443 = 0x01BB
    }

    #[test]
    fn encode_socks5_ipv6() {
        let addr = Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80));
        let mut buf = BytesMut::new();
        addr.encode_socks5(&mut buf);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 1 + 16 + 2); // atyp + ipv6 + port
        assert_eq!(&buf[17..19], &[0x00, 0x50]); // port 80 = 0x0050
    }

    #[test]
    fn encode_socks5_domain() {
        let addr = Address::Domain("test.com".to_string(), 8080);
        let mut buf = BytesMut::new();
        addr.encode_socks5(&mut buf);
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 8); // domain length
        assert_eq!(&buf[2..10], b"test.com");
        assert_eq!(u16::from_be_bytes([buf[10], buf[11]]), 8080);
    }

    #[test]
    fn parse_socks5_udp_addr_ipv4() {
        let data = [0x01, 127, 0, 0, 1, 0x00, 0x50]; // 127.0.0.1:80
        let (addr, consumed) = Address::parse_socks5_udp_addr(&data).unwrap();
        assert_eq!(addr, Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn parse_socks5_udp_addr_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0u8; 16]); // ::0
        data.extend_from_slice(&[0x01, 0xBB]); // port 443
        let (addr, consumed) = Address::parse_socks5_udp_addr(&data).unwrap();
        assert_eq!(addr, Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443)));
        assert_eq!(consumed, 19);
    }

    #[test]
    fn parse_socks5_udp_addr_domain() {
        let mut data = vec![0x03, 11]; // atyp=domain, len=11
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x01, 0xBB]); // port 443
        let (addr, consumed) = Address::parse_socks5_udp_addr(&data).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 443));
        assert_eq!(consumed, 15);
    }

    #[test]
    fn parse_socks5_udp_addr_empty() {
        assert!(Address::parse_socks5_udp_addr(&[]).is_err());
    }

    #[test]
    fn parse_socks5_udp_addr_insufficient() {
        assert!(Address::parse_socks5_udp_addr(&[0x01, 1, 2]).is_err());
    }

    #[test]
    fn encode_parse_socks5_roundtrip() {
        let addrs = vec![
            Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)),
            Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443)),
            Address::Domain("example.com".to_string(), 80),
        ];
        for addr in addrs {
            let mut buf = BytesMut::new();
            addr.encode_socks5(&mut buf);
            let (parsed, consumed) = Address::parse_socks5_udp_addr(&buf).unwrap();
            assert_eq!(parsed, addr);
            assert_eq!(consumed, buf.len());
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
