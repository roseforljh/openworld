use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// SOCKS5 出站代理
///
/// 实现 RFC 1928 SOCKS5 协议的客户端侧：
/// - 方法协商（无认证 / 用户名密码）
/// - CONNECT 命令 (TCP)
/// - UDP ASSOCIATE 命令 (UDP)
pub struct Socks5Outbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    username: Option<String>,
    password: Option<String>,
    dialer_config: Option<DialerConfig>,
}

impl Socks5Outbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings.address.as_ref().ok_or_else(|| {
            anyhow::anyhow!("socks5 outbound '{}' missing 'address'", config.tag)
        })?;
        let port = settings.port.ok_or_else(|| {
            anyhow::anyhow!("socks5 outbound '{}' missing 'port'", config.tag)
        })?;

        let username = settings.username.clone().or_else(|| settings.uuid.clone());
        let password = settings.password.clone();

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            auth = username.is_some(),
            "socks5 outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            username,
            password,
            dialer_config: settings.dialer.clone(),
        })
    }

    fn dialer(&self) -> Dialer {
        match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        }
    }

    /// 执行 SOCKS5 握手（方法协商 + 可选认证），返回已认证的流
    async fn handshake(&self, stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<()> {
        let has_auth = self.username.is_some() && self.password.is_some();

        // === 方法协商 ===
        if has_auth {
            // 支持 NO_AUTH(0x00) 和 USERNAME_PASSWORD(0x02)
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            // 仅 NO_AUTH(0x00)
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;

        if resp[0] != 0x05 {
            anyhow::bail!("socks5: server returned unsupported version: 0x{:02x}", resp[0]);
        }

        match resp[1] {
            0x00 => {
                // NO_AUTH — 握手完成
                debug!("socks5: no authentication required");
            }
            0x02 => {
                // USERNAME/PASSWORD auth (RFC 1929)
                let username = self.username.as_ref().unwrap();
                let password = self.password.as_ref().unwrap();

                let mut auth_req = Vec::with_capacity(3 + username.len() + password.len());
                auth_req.push(0x01); // auth version
                auth_req.push(username.len() as u8);
                auth_req.extend_from_slice(username.as_bytes());
                auth_req.push(password.len() as u8);
                auth_req.extend_from_slice(password.as_bytes());
                stream.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;

                if auth_resp[1] != 0x00 {
                    anyhow::bail!("socks5: authentication failed (status: 0x{:02x})", auth_resp[1]);
                }
                debug!("socks5: authentication successful");
            }
            0xFF => {
                anyhow::bail!("socks5: server rejected all authentication methods");
            }
            method => {
                anyhow::bail!("socks5: unsupported auth method selected: 0x{:02x}", method);
            }
        }

        Ok(())
    }

    /// 发送 SOCKS5 请求并读取回复
    async fn send_request(
        &self,
        stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        cmd: u8,
        target: &Address,
    ) -> Result<Address> {
        let mut req = BytesMut::with_capacity(64);
        req.put_u8(0x05); // VER
        req.put_u8(cmd);  // CMD
        req.put_u8(0x00); // RSV

        // 编码目标地址 [ATYP][ADDR][PORT]
        target.encode_socks5(&mut req);

        stream.write_all(&req).await?;

        // 读取回复
        let mut resp_head = [0u8; 3];
        stream.read_exact(&mut resp_head).await?;

        if resp_head[0] != 0x05 {
            anyhow::bail!("socks5: invalid reply version: 0x{:02x}", resp_head[0]);
        }
        if resp_head[1] != 0x00 {
            let reason = match resp_head[1] {
                0x01 => "general failure",
                0x02 => "connection not allowed",
                0x03 => "network unreachable",
                0x04 => "host unreachable",
                0x05 => "connection refused",
                0x06 => "TTL expired",
                0x07 => "command not supported",
                0x08 => "address type not supported",
                _ => "unknown error",
            };
            anyhow::bail!("socks5: request failed: {} (0x{:02x})", reason, resp_head[1]);
        }

        // 读取 BND.ADDR
        let atyp = {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            b[0]
        };
        let bind_addr = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
                Address::Ip(SocketAddr::new(ip, port))
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let mut domain = vec![0u8; len_buf[0] as usize];
                stream.read_exact(&mut domain).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                Address::Domain(String::from_utf8_lossy(&domain).to_string(), port)
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = IpAddr::V6(addr.into());
                Address::Ip(SocketAddr::new(ip, port))
            }
            _ => {
                anyhow::bail!("socks5: unsupported bind address type: 0x{:02x}", atyp);
            }
        };

        Ok(bind_addr)
    }
}

#[async_trait]
impl OutboundHandler for Socks5Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(target = %session.target, server = %self.server_addr, port = self.server_port, "socks5 CONNECT");

        let dialer = self.dialer();
        let mut stream = dialer.connect_host(&self.server_addr, self.server_port).await?;

        // 握手 + 认证
        self.handshake(&mut stream).await?;

        // 发送 CONNECT 命令
        let _bind = self.send_request(&mut stream, 0x01, &session.target).await?;

        debug!(target = %session.target, "socks5 CONNECT tunnel established");
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        debug!(target = %session.target, server = %self.server_addr, port = self.server_port, "socks5 UDP ASSOCIATE");

        let dialer = self.dialer();
        let mut tcp_stream = dialer.connect_host(&self.server_addr, self.server_port).await?;

        // 握手 + 认证
        self.handshake(&mut tcp_stream).await?;

        // 发送 UDP ASSOCIATE 命令（目标为 0.0.0.0:0 表示任意地址）
        let placeholder = Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let bind_addr = self.send_request(&mut tcp_stream, 0x03, &placeholder).await?;

        // 解析服务器绑定的 UDP 中继地址
        let relay_addr: SocketAddr = match &bind_addr {
            Address::Ip(addr) => {
                // 如果服务器返回 0.0.0.0，使用 TCP 连接的服务器地址
                if addr.ip().is_unspecified() {
                    let ip: IpAddr = self.server_addr.parse()
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                    SocketAddr::new(ip, addr.port())
                } else {
                    *addr
                }
            }
            Address::Domain(host, port) => {
                // DNS 解析
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
                    .await?
                    .collect();
                *addrs.first()
                    .ok_or_else(|| anyhow::anyhow!("socks5: cannot resolve UDP relay address: {}", host))?
            }
        };

        debug!(relay = %relay_addr, "socks5 UDP relay address");

        // 绑定本地 UDP socket
        let local_bind = if relay_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let udp_socket = UdpSocket::bind(local_bind).await?;

        let transport = Socks5UdpOutTransport {
            socket: Arc::new(udp_socket),
            relay_addr,
            // 保持 TCP 连接活跃（SOCKS5 规范：TCP 连接断开时 UDP 中继自动关闭）
            _tcp_keepalive: Arc::new(Mutex::new(Box::new(tcp_stream))),
        };

        Ok(Box::new(transport))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// SOCKS5 UDP 出站传输
///
/// 通过 SOCKS5 UDP ASSOCIATE 中继 UDP 数据包。
/// TCP 控制连接在 _tcp_keepalive 中保活。
struct Socks5UdpOutTransport {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    _tcp_keepalive: Arc<Mutex<ProxyStream>>,
}

#[async_trait]
impl UdpTransport for Socks5UdpOutTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        // 封装 SOCKS5 UDP 头: [RSV: 2B=0][FRAG: 1B=0][ATYP+ADDR+PORT][DATA]
        let mut buf = BytesMut::with_capacity(3 + 32 + packet.data.len());
        buf.put_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG=0
        packet.addr.encode_socks5(&mut buf);
        buf.put_slice(&packet.data);

        self.socket.send_to(&buf, self.relay_addr).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        loop {
            let mut buf = vec![0u8; 65535];
            let (n, _from) = self.socket.recv_from(&mut buf).await?;
            let data = &buf[..n];

            // 解析 SOCKS5 UDP 头: [RSV: 2B][FRAG: 1B][ATYP+ADDR+PORT][DATA]
            if data.len() < 4 {
                continue; // 太短，跳过
            }

            let frag = data[2];
            if frag != 0 {
                continue; // 丢弃分片
            }

            let (addr, addr_len) = match Address::parse_socks5_udp_addr(&data[3..]) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let payload_start = 3 + addr_len;
            if payload_start > data.len() {
                continue;
            }

            return Ok(UdpPacket {
                addr,
                data: Bytes::copy_from_slice(&data[payload_start..]),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn socks5_outbound_creation() {
        let config = OutboundConfig {
            tag: "socks5-out".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings {
                address: Some("proxy.example.com".to_string()),
                port: Some(1080),
                ..Default::default()
            },
        };
        let outbound = Socks5Outbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "socks5-out");
        assert_eq!(outbound.server_port, 1080);
        assert!(outbound.username.is_none());
    }

    #[test]
    fn socks5_outbound_with_auth() {
        let config = OutboundConfig {
            tag: "socks5-auth".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings {
                address: Some("proxy.example.com".to_string()),
                port: Some(1080),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        };
        let outbound = Socks5Outbound::new(&config).unwrap();
        assert_eq!(outbound.username.as_deref(), Some("user"));
        assert_eq!(outbound.password.as_deref(), Some("pass"));
    }

    #[test]
    fn socks5_outbound_missing_address() {
        let config = OutboundConfig {
            tag: "bad".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings::default(),
        };
        assert!(Socks5Outbound::new(&config).is_err());
    }

    #[test]
    fn socks5_outbound_uuid_fallback_username() {
        // 如果没有 username，fallback 到 uuid 字段
        let config = OutboundConfig {
            tag: "socks5-uuid".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings {
                address: Some("proxy.example.com".to_string()),
                port: Some(1080),
                uuid: Some("user-as-uuid".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        };
        let outbound = Socks5Outbound::new(&config).unwrap();
        assert_eq!(outbound.username.as_deref(), Some("user-as-uuid"));
    }

    #[tokio::test]
    async fn socks5_outbound_connect_no_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = OutboundConfig {
            tag: "socks5-test".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(port),
                ..Default::default()
            },
        };
        let outbound = Socks5Outbound::new(&config).unwrap();

        // 模拟 SOCKS5 服务器
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // 方法协商
            let mut buf = [0u8; 3];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05); // VER
            assert_eq!(buf[1], 0x01); // NMETHODS=1
            assert_eq!(buf[2], 0x00); // NO_AUTH

            // 选择 NO_AUTH
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            // 读取 CONNECT 请求
            let mut req = vec![0u8; 256];
            let n = sock.read(&mut req).await.unwrap();
            assert!(n >= 4);
            assert_eq!(req[0], 0x05); // VER
            assert_eq!(req[1], 0x01); // CONNECT

            // 回复成功
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                .await
                .unwrap();
        });

        let session = Session {
            target: Address::Domain("example.com".to_string(), 80),
            source: None,
            inbound_tag: String::new(),
            network: crate::proxy::Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };

        let stream = outbound.connect(&session).await.unwrap();
        drop(stream);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_outbound_connect_with_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = OutboundConfig {
            tag: "socks5-auth-test".to_string(),
            protocol: "socks5".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(port),
                username: Some("admin".to_string()),
                password: Some("secret".to_string()),
                ..Default::default()
            },
        };
        let outbound = Socks5Outbound::new(&config).unwrap();

        // 模拟 SOCKS5 服务器（带认证）
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // 方法协商
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05);
            assert_eq!(buf[1], 0x02); // NMETHODS=2
            // methods: 0x00 和 0x02

            // 选择 USERNAME/PASSWORD
            sock.write_all(&[0x05, 0x02]).await.unwrap();

            // 读取认证
            let mut auth = vec![0u8; 64];
            let n = sock.read(&mut auth).await.unwrap();
            assert!(n > 2);
            assert_eq!(auth[0], 0x01); // auth ver
            let ulen = auth[1] as usize;
            let username = String::from_utf8_lossy(&auth[2..2 + ulen]).to_string();
            let plen = auth[2 + ulen] as usize;
            let password = String::from_utf8_lossy(&auth[3 + ulen..3 + ulen + plen]).to_string();
            assert_eq!(username, "admin");
            assert_eq!(password, "secret");

            // 认证成功
            sock.write_all(&[0x01, 0x00]).await.unwrap();

            // 读取 CONNECT 请求
            let mut req = vec![0u8; 256];
            let _n = sock.read(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x01);

            // 回复成功
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let session = Session {
            target: Address::Ip("1.2.3.4:443".parse().unwrap()),
            source: None,
            inbound_tag: String::new(),
            network: crate::proxy::Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };

        let stream = outbound.connect(&session).await.unwrap();
        drop(stream);
        handle.await.unwrap();
    }
}
