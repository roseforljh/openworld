use std::collections::HashSet;

use anyhow::Result;

use crate::common::Address;
use crate::config::types::InboundConfig;
use crate::proxy::outbound::hysteria2::protocol;

/// Hysteria2 入站处理器（服务端）
pub struct Hysteria2Inbound {
    #[allow(dead_code)]
    tag: String,
    passwords: HashSet<String>,
    listen_addr: String,
    listen_port: u16,
}

impl Hysteria2Inbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let mut passwords = HashSet::new();
        if let Some(pw) = config.settings.password.as_ref() {
            passwords.insert(pw.clone());
        }
        if passwords.is_empty() {
            anyhow::bail!(
                "hysteria2 inbound '{}' requires 'settings.password'",
                config.tag
            );
        }

        Ok(Self {
            tag: config.tag.clone(),
            passwords,
            listen_addr: config.listen.clone(),
            listen_port: config.port,
        })
    }

    /// 验证 HTTP/3 认证请求中的密码
    pub fn verify_password(&self, password: &str) -> bool {
        self.passwords.contains(password)
    }

    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }
}

/// Hysteria2 入站请求解析结果
#[derive(Debug, Clone)]
pub struct Hy2InboundRequest {
    pub request_type: Hy2RequestType,
    pub target: Address,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Hy2RequestType {
    Tcp,
    Udp,
}

/// 从 QUIC 双向流中解析 Hysteria2 TCP 请求头
pub async fn parse_tcp_request(
    recv: &mut quinn::RecvStream,
) -> Result<Hy2InboundRequest> {
    use crate::proxy::outbound::hysteria2::protocol::decode_varint_from_buf;

    // 读取足够的数据：request_id(varint) + addr_len(varint) + addr + padding_len(varint) + padding
    let mut header = [0u8; 4];
    read_exact_quinn(recv, &mut header[..1]).await?;

    // 解析 request ID varint
    let first_byte = header[0];
    let varint_len = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    let request_id = if varint_len == 1 {
        (first_byte & 0x3F) as u64
    } else {
        let mut buf = vec![first_byte];
        let mut remaining = vec![0u8; varint_len - 1];
        read_exact_quinn(recv, &mut remaining).await?;
        buf.extend_from_slice(&remaining);
        let (val, _) = decode_varint_from_buf(&buf)?;
        val
    };

    // 0x401 = TCP, 0x402 = UDP
    let req_type = if request_id == 0x401 {
        Hy2RequestType::Tcp
    } else if request_id == 0x402 {
        Hy2RequestType::Udp
    } else {
        anyhow::bail!("unknown hysteria2 request type: 0x{:x}", request_id);
    };

    // 读取地址长度 varint
    read_exact_quinn(recv, &mut header[..1]).await?;
    let first = header[0];
    let addr_varint_len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    let addr_len = if addr_varint_len == 1 {
        (first & 0x3F) as u64
    } else {
        let mut buf = vec![first];
        let mut remaining = vec![0u8; addr_varint_len - 1];
        read_exact_quinn(recv, &mut remaining).await?;
        buf.extend_from_slice(&remaining);
        let (val, _) = decode_varint_from_buf(&buf)?;
        val
    };

    // 读取地址字符串
    let mut addr_buf = vec![0u8; addr_len as usize];
    if addr_len > 0 {
        read_exact_quinn(recv, &mut addr_buf).await?;
    }
    let addr_str = String::from_utf8(addr_buf)?;

    // 读取 padding 长度 varint 并跳过
    read_exact_quinn(recv, &mut header[..1]).await?;
    let pad_first = header[0];
    let pad_varint_len = match pad_first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    let pad_len = if pad_varint_len == 1 {
        (pad_first & 0x3F) as u64
    } else {
        let mut buf = vec![pad_first];
        let mut remaining = vec![0u8; pad_varint_len - 1];
        read_exact_quinn(recv, &mut remaining).await?;
        buf.extend_from_slice(&remaining);
        let (val, _) = decode_varint_from_buf(&buf)?;
        val
    };
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len as usize];
        read_exact_quinn(recv, &mut pad).await?;
    }

    // 解析地址
    let target = parse_hy2_addr(&addr_str)?;

    Ok(Hy2InboundRequest {
        request_type: req_type,
        target,
    })
}

/// 发送 Hysteria2 TCP 成功响应
pub async fn write_tcp_response_ok(send: &mut quinn::SendStream) -> Result<()> {
    #[allow(unused_imports)]
    use tokio::io::AsyncWriteExt;
    let mut buf = Vec::new();
    buf.push(0x00); // status OK
    buf.push(0x00); // msg_len = 0
    buf.push(0x00); // padding_len = 0
    send.write_all(&buf).await?;
    Ok(())
}

/// 发送 Hysteria2 TCP 错误响应
pub async fn write_tcp_response_err(send: &mut quinn::SendStream, msg: &str) -> Result<()> {
    #[allow(unused_imports)]
    use tokio::io::AsyncWriteExt;
    let msg_bytes = msg.as_bytes();
    let mut buf = Vec::new();
    buf.push(0x01); // status Error
    buf.extend_from_slice(&protocol::encode_varint(msg_bytes.len() as u64));
    buf.extend_from_slice(msg_bytes);
    buf.push(0x00); // padding_len = 0
    send.write_all(&buf).await?;
    Ok(())
}

fn parse_hy2_addr(s: &str) -> Result<Address> {
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

async fn read_exact_quinn(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = recv
            .read(&mut buf[offset..])
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream closed unexpectedly"))?;
        offset += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hy2_inbound_requires_password() {
        let config = InboundConfig {
            tag: "hy2-in".to_string(),
            protocol: "hysteria2".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 443,
            sniffing: Default::default(),
            settings: Default::default(),
        };
        assert!(Hysteria2Inbound::new(&config).is_err());
    }

    #[test]
    fn hy2_inbound_with_password() {
        let mut settings = crate::config::types::InboundSettings::default();
        settings.password = Some("test123".to_string());
        let config = InboundConfig {
            tag: "hy2-in".to_string(),
            protocol: "hysteria2".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 443,
            sniffing: Default::default(),
            settings,
        };
        let inbound = Hysteria2Inbound::new(&config).unwrap();
        assert!(inbound.verify_password("test123"));
        assert!(!inbound.verify_password("wrong"));
    }

    #[test]
    fn parse_hy2_addr_ipv4() {
        let addr = parse_hy2_addr("1.2.3.4:80").unwrap();
        match addr {
            Address::Ip(sa) => {
                assert_eq!(sa.port(), 80);
            }
            _ => panic!("expected IP address"),
        }
    }

    #[test]
    fn parse_hy2_addr_domain() {
        let addr = parse_hy2_addr("example.com:443").unwrap();
        match addr {
            Address::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[test]
    fn parse_hy2_addr_invalid() {
        assert!(parse_hy2_addr("no-port").is_err());
    }

    #[test]
    fn hy2_request_type_eq() {
        assert_eq!(Hy2RequestType::Tcp, Hy2RequestType::Tcp);
        assert_ne!(Hy2RequestType::Tcp, Hy2RequestType::Udp);
    }

    #[test]
    fn hy2_inbound_listen_info() {
        let mut settings = crate::config::types::InboundSettings::default();
        settings.password = Some("pw".to_string());
        let config = InboundConfig {
            tag: "hy2-in".to_string(),
            protocol: "hysteria2".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 8443,
            sniffing: Default::default(),
            settings,
        };
        let inbound = Hysteria2Inbound::new(&config).unwrap();
        assert_eq!(inbound.listen_addr(), "127.0.0.1");
        assert_eq!(inbound.listen_port(), 8443);
    }
}
