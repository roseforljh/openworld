use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, ProxyStream, UdpPacket, UdpTransport};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

pub struct Socks5Inbound {
    tag: String,
    listen: String,
    /// 认证用户列表 (username, password)，为空则不要求认证
    auth_users: Vec<(String, String)>,
}

impl Socks5Inbound {
    pub fn new(tag: String, listen: String) -> Self {
        Self { tag, listen, auth_users: Vec::new() }
    }

    pub fn with_auth(mut self, users: Vec<(String, String)>) -> Self {
        self.auth_users = users;
        self
    }
}

#[async_trait]
impl InboundHandler for Socks5Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let mut stream = stream;

        // === 阶段 1: 方法协商 ===
        let ver = read_u8(&mut stream).await?;
        if ver != 0x05 {
            bail!("unsupported SOCKS version: 0x{:02x}", ver);
        }

        let nmethods = read_u8(&mut stream).await? as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        if !self.auth_users.is_empty() {
            // 需要认证：检查客户端是否支持 0x02 (USERNAME/PASSWORD)
            if !methods.contains(&0x02) {
                // 客户端不支持用户名/密码认证
                stream.write_all(&[0x05, 0xFF]).await?;
                bail!("SOCKS5 client does not support username/password auth");
            }

            // 选择方法 0x02
            stream.write_all(&[0x05, 0x02]).await?;

            // RFC 1929: 用户名/密码子协商
            let auth_ver = read_u8(&mut stream).await?;
            if auth_ver != 0x01 {
                bail!("unsupported SOCKS5 auth version: 0x{:02x}", auth_ver);
            }

            let ulen = read_u8(&mut stream).await? as usize;
            let mut username = vec![0u8; ulen];
            stream.read_exact(&mut username).await?;
            let username = String::from_utf8_lossy(&username).to_string();

            let plen = read_u8(&mut stream).await? as usize;
            let mut password = vec![0u8; plen];
            stream.read_exact(&mut password).await?;
            let password = String::from_utf8_lossy(&password).to_string();

            let authenticated = self.auth_users.iter().any(|(u, p)| u == &username && p == &password);

            if !authenticated {
                // 认证失败
                stream.write_all(&[0x01, 0x01]).await?;
                bail!("SOCKS5 auth failed for user '{}'", username);
            }

            // 认证成功
            stream.write_all(&[0x01, 0x00]).await?;
            debug!(user = %username, "SOCKS5 auth success");
        } else {
            // 无认证要求：选择 0x00
            stream.write_all(&[0x05, 0x00]).await?;
        }

        // === 阶段 2: 请求 ===
        let ver = read_u8(&mut stream).await?;
        if ver != 0x05 {
            bail!("invalid SOCKS5 request version: 0x{:02x}", ver);
        }

        let cmd = read_u8(&mut stream).await?;
        let _rsv = read_u8(&mut stream).await?;

        // 读取目标地址
        let target = read_address(&mut stream).await?;

        match cmd {
            0x01 => {
                // CONNECT (TCP)
                debug!(target = %target, "SOCKS5 CONNECT request");

                // 回复成功
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;

                let session = Session {
                    target,
                    source: Some(source),
                    inbound_tag: self.tag.clone(),
                    network: Network::Tcp,
                    sniff: false,
                    detected_protocol: None,
                };

                Ok(InboundResult {
                    session,
                    stream,
                    udp_transport: None,
                })
            }
            0x03 => {
                // UDP ASSOCIATE
                debug!(source = %source, "SOCKS5 UDP ASSOCIATE request");

                // 绑定 UDP socket
                let udp_socket = UdpSocket::bind(format!("{}:0", self.listen)).await?;
                let local_addr = udp_socket.local_addr()?;
                debug!(bind = %local_addr, "SOCKS5 UDP relay socket bound");

                // 回复 BND.ADDR:BND.PORT
                let mut reply = BytesMut::with_capacity(32);
                reply.put_slice(&[0x05, 0x00, 0x00]); // VER, REP=success, RSV
                match local_addr {
                    SocketAddr::V4(v4) => {
                        reply.put_u8(0x01);
                        reply.put_slice(&v4.ip().octets());
                        reply.put_u16(v4.port());
                    }
                    SocketAddr::V6(v6) => {
                        reply.put_u8(0x04);
                        reply.put_slice(&v6.ip().octets());
                        reply.put_u16(v6.port());
                    }
                }
                stream.write_all(&reply).await?;

                let udp_relay = Socks5UdpRelay {
                    socket: Arc::new(udp_socket),
                    client_addr: Mutex::new(None),
                    source,
                };

                // UDP ASSOCIATE 的 target 不重要（客户端在 UDP 包中指定实际目标）
                // 使用一个占位地址
                let session = Session {
                    target: Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                    source: Some(source),
                    inbound_tag: self.tag.clone(),
                    network: Network::Udp,
                    sniff: false,
                    detected_protocol: None,
                };

                Ok(InboundResult {
                    session,
                    stream,
                    udp_transport: Some(Box::new(udp_relay)),
                })
            }
            _ => {
                // 不支持的命令
                stream
                    .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                bail!("unsupported SOCKS5 command: 0x{:02x}", cmd);
            }
        }
    }
}

/// 从流中读取 SOCKS5 地址 [ATYP][ADDR][PORT]
async fn read_address(stream: &mut ProxyStream) -> Result<Address> {
    let atyp = read_u8(stream).await?;
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = read_u16_be(stream).await?;
            Address::from_socks5(0x01, &addr, port)
        }
        0x03 => {
            let len = read_u8(stream).await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = read_u16_be(stream).await?;
            Address::from_socks5(0x03, &domain, port)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = read_u16_be(stream).await?;
            Address::from_socks5(0x04, &addr, port)
        }
        _ => {
            bail!("unsupported SOCKS5 address type: 0x{:02x}", atyp);
        }
    }
}

/// SOCKS5 UDP 中继
struct Socks5UdpRelay {
    socket: Arc<UdpSocket>,
    /// 客户端 UDP 地址（首次收到包时记录）
    client_addr: Mutex<Option<SocketAddr>>,
    /// 客户端 TCP 来源地址（用于验证）
    source: SocketAddr,
}

#[async_trait]
impl UdpTransport for Socks5UdpRelay {
    async fn recv(&self) -> Result<UdpPacket> {
        loop {
            let mut buf = vec![0u8; 65535];
            let (n, from) = self.socket.recv_from(&mut buf).await?;

            // 验证来源 IP 与 TCP 控制连接一致
            if from.ip() != self.source.ip() {
                debug!(from = %from, expected = %self.source.ip(), "SOCKS5 UDP: ignoring packet from unknown source");
                continue;
            }

            // 记录客户端 UDP 地址
            {
                let mut client = self.client_addr.lock().await;
                if client.is_none() {
                    *client = Some(from);
                    debug!(client_udp = %from, "SOCKS5 UDP: client address recorded");
                }
            }

            let data = &buf[..n];

            // 解析 SOCKS5 UDP 头: [RSV: 2B][FRAG: 1B][ATYP+ADDR+PORT][DATA]
            if data.len() < 4 {
                bail!("SOCKS5 UDP packet too short");
            }

            let frag = data[2];
            if frag != 0 {
                // 丢弃分片包
                debug!(frag = frag, "SOCKS5 UDP: dropping fragmented packet");
                continue;
            }

            // 从 offset 3 开始解析地址
            let (addr, addr_len) = Address::parse_socks5_udp_addr(&data[3..])?;
            let payload_start = 3 + addr_len;
            let payload = Bytes::copy_from_slice(&data[payload_start..]);

            return Ok(UdpPacket {
                addr,
                data: payload,
            });
        }
    }

    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let client = self.client_addr.lock().await;
        let client_addr =
            client.ok_or_else(|| anyhow::anyhow!("SOCKS5 UDP: client address not yet known"))?;

        // 封装 SOCKS5 UDP 头: [RSV: 2B=0][FRAG: 1B=0][ATYP+ADDR+PORT][DATA]
        let mut buf = BytesMut::with_capacity(3 + 32 + packet.data.len());
        buf.put_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
        packet.addr.encode_socks5(&mut buf);
        buf.put_slice(&packet.data);

        self.socket.send_to(&buf, client_addr).await?;
        Ok(())
    }
}

async fn read_u8(stream: &mut ProxyStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16_be(stream: &mut ProxyStream) -> Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_udp_header_parse() {
        // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) + DATA
        let mut pkt = vec![0x00, 0x00, 0x00]; // RSV + FRAG=0
        pkt.push(0x01); // ATYP=IPv4
        pkt.extend_from_slice(&[8, 8, 8, 8]); // 8.8.8.8
        pkt.extend_from_slice(&[0x00, 0x35]); // port 53
        pkt.extend_from_slice(b"hello"); // payload

        let frag = pkt[2];
        assert_eq!(frag, 0);

        let (addr, addr_len) = Address::parse_socks5_udp_addr(&pkt[3..]).unwrap();
        assert_eq!(addr, Address::Ip("8.8.8.8:53".parse().unwrap()));
        assert_eq!(addr_len, 7);

        let payload = &pkt[3 + addr_len..];
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn socks5_udp_header_build() {
        let addr = Address::Ip("1.2.3.4:53".parse().unwrap());
        let data = Bytes::from_static(b"test");

        let mut buf = BytesMut::with_capacity(64);
        buf.put_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
        addr.encode_socks5(&mut buf);
        buf.put_slice(&data);

        // 验证: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) + "test"(4) = 14
        assert_eq!(buf.len(), 14);
        assert_eq!(buf[3], 0x01); // ATYP=IPv4
    }

    #[test]
    fn socks5_udp_header_domain() {
        let mut pkt = vec![0x00, 0x00, 0x00]; // RSV + FRAG=0
        pkt.push(0x03); // ATYP=Domain
        pkt.push(11); // domain length
        pkt.extend_from_slice(b"example.com");
        pkt.extend_from_slice(&[0x01, 0xBB]); // port 443
        pkt.extend_from_slice(b"data");

        let (addr, addr_len) = Address::parse_socks5_udp_addr(&pkt[3..]).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 443));
        assert_eq!(addr_len, 15);

        let payload = &pkt[3 + addr_len..];
        assert_eq!(payload, b"data");
    }
}
