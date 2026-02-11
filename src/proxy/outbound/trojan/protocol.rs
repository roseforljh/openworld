use anyhow::Result;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, ProxyStream};

/// Trojan 命令
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// 计算 Trojan 密码的 SHA224 hex 散列
pub fn password_hash(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 编码 SOCKS5 风格的地址（ATYP + ADDR + PORT）
fn encode_trojan_addr(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        Address::Ip(sock_addr) => match sock_addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(0x01); // IPv4
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(0x04); // IPv6
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        Address::Domain(domain, port) => {
            buf.push(0x03); // Domain
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// 写入 Trojan 请求头
///
/// 格式:
/// [hex(SHA224(password)): 56 bytes ASCII]
/// [CRLF: \r\n]
/// [CMD: 1 byte]
/// [ATYP + ADDR + PORT: variable]
/// [CRLF: \r\n]
pub async fn write_request(
    stream: &mut ProxyStream,
    password_hash: &str,
    target: &Address,
    command: u8,
) -> Result<()> {
    let mut buf = Vec::with_capacity(128);

    // SHA224 hex hash (56 bytes)
    buf.extend_from_slice(password_hash.as_bytes());
    // CRLF
    buf.extend_from_slice(b"\r\n");
    // Command
    buf.push(command);
    // Address (ATYP + ADDR + PORT)
    buf.extend_from_slice(&encode_trojan_addr(target));
    // CRLF
    buf.extend_from_slice(b"\r\n");

    stream.write_all(&buf).await?;
    Ok(())
}

/// Trojan UDP 帧格式:
/// [ATYP: 1B] [ADDR: variable] [PORT: 2B BE] [LENGTH: 2B BE] [CRLF] [PAYLOAD: LENGTH bytes]

/// 写入一个 Trojan UDP 帧
pub async fn write_udp_frame(
    stream: &mut ProxyStream,
    addr: &Address,
    payload: &[u8],
) -> Result<()> {
    let addr_bytes = encode_trojan_addr(addr);
    let length = payload.len() as u16;

    let mut buf = Vec::with_capacity(addr_bytes.len() + 2 + 2 + payload.len());
    buf.extend_from_slice(&addr_bytes);
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(payload);

    stream.write_all(&buf).await?;
    Ok(())
}

/// 读取一个 Trojan UDP 帧，返回 (Address, payload)
pub async fn read_udp_frame(stream: &mut ProxyStream) -> Result<(Address, Vec<u8>)> {
    // 读取 ATYP
    let atyp = stream.read_u8().await?;

    let addr = match atyp {
        0x01 => {
            // IPv4
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::Ipv4Addr::from(ip_bytes);
            Address::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            )))
        }
        0x03 => {
            // Domain
            let len = stream.read_u8().await?;
            let mut domain_bytes = vec![0u8; len as usize];
            stream.read_exact(&mut domain_bytes).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain_bytes)?;
            Address::Domain(domain, port)
        }
        0x04 => {
            // IPv6
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            Address::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, port, 0, 0,
            )))
        }
        _ => anyhow::bail!("trojan: unsupported address type: 0x{:02x}", atyp),
    };

    // 读取长度
    let length = stream.read_u16().await?;

    // 读取 CRLF
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;

    // 读取 payload
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload).await?;

    Ok((addr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let hash = password_hash("password123");
        assert_eq!(hash.len(), 56); // SHA224 = 28 bytes = 56 hex chars
    }

    #[test]
    fn test_password_hash_deterministic() {
        let h1 = password_hash("test");
        let h2 = password_hash("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_encode_trojan_addr_ipv4() {
        let addr = Address::Ip("1.2.3.4:443".parse().unwrap());
        let encoded = encode_trojan_addr(&addr);
        assert_eq!(encoded[0], 0x01); // IPv4
        assert_eq!(&encoded[1..5], &[1, 2, 3, 4]);
        assert_eq!(&encoded[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn test_encode_trojan_addr_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let encoded = encode_trojan_addr(&addr);
        assert_eq!(encoded[0], 0x03); // Domain
        assert_eq!(encoded[1], 11); // "example.com".len()
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &443u16.to_be_bytes());
    }

    #[test]
    fn test_encode_trojan_addr_ipv6() {
        let addr = Address::Ip("[::1]:8080".parse().unwrap());
        let encoded = encode_trojan_addr(&addr);
        assert_eq!(encoded[0], 0x04); // IPv6
        assert_eq!(encoded.len(), 1 + 16 + 2); // ATYP + 16 bytes IPv6 + 2 bytes port
    }
}
