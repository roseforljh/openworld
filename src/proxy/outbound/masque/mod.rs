// MASQUE 出站 — 主模块
//
// 实现 IETF MASQUE CONNECT-IP (RFC 9484) 出站代理。
// 兼容 Cloudflare WARP / mihomo MASQUE 协议。
//
// 架构：
//   OutboundHandler → smoltcp TCP/UDP → IP 包 → CONNECT-IP Capsule → HTTP/3 → QUIC
//
// 依赖：quinn（QUIC），h3/h3-quinn（HTTP/3），smoltcp（用户态网络栈）

pub mod connect_ip;
pub mod stack;
pub mod tls;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};

use crate::common::{Address, BoxUdpTransport, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

use connect_ip::*;
use stack::SharedStack;

/// MASQUE 出站配置
pub struct MasqueOutbound {
    tag: String,
    /// 服务器地址
    server: String,
    /// 服务器端口
    port: u16,
    /// ECDSA 私钥 PEM 格式
    private_key_pem: String,
    /// 服务端公钥 DER（Base64 解码后）
    public_key_der: Vec<u8>,
    /// 本地虚拟 IPv4 地址
    local_ipv4: Option<IpAddr>,
    /// 本地虚拟 IPv6 地址
    #[allow(dead_code)]
    local_ipv6: Option<IpAddr>,
    /// CONNECT-IP URI
    #[allow(dead_code)]
    uri: String,
    /// TLS SNI
    sni: String,
    /// MTU
    mtu: u16,
    /// 拥塞控制算法
    congestion: String,
    /// UDP 支持
    #[allow(dead_code)]
    udp: bool,
    /// 隧道状态
    tunnel: Mutex<Option<TunnelState>>,
}

/// 活跃的 MASQUE 隧道
struct TunnelState {
    /// smoltcp 用户态网络栈
    stack: SharedStack,
    /// QUIC 连接
    #[allow(dead_code)]
    quic_conn: quinn::Connection,
    /// 隧道后台任务 handle
    _tunnel_task: tokio::task::JoinHandle<()>,
}

impl MasqueOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;

        let server = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("masque: 缺少 address 配置"))?
            .clone();
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("masque: 缺少 port 配置"))?;

        // 解析 ECDSA 密钥
        let private_key_pem = settings
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("masque: 缺少 private-key 配置"))?
            .clone();
        let public_key_b64 = settings
            .public_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("masque: 缺少 public-key 配置"))?;

        let public_key_der = tls::decode_base64(public_key_b64)?;

        // 解析本地虚拟 IP
        let local_ipv4 = settings
            .local_address
            .as_ref()
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<IpAddr>().ok())
            .filter(|ip| ip.is_ipv4());

        let local_ipv6 = settings.local_address.as_ref().and_then(|s| {
            // 尝试解析 ipv6 部分
            if s.contains(':') && !s.contains('.') {
                s.split('/').next().and_then(|ip| ip.parse::<IpAddr>().ok())
            } else {
                None
            }
        });

        let uri = DEFAULT_CONNECT_URI.to_string();
        let sni = settings
            .sni
            .clone()
            .unwrap_or_else(|| DEFAULT_CONNECT_SNI.to_string());
        let mtu = settings.mtu.unwrap_or(1280);
        let congestion = settings
            .congestion_control
            .clone()
            .unwrap_or_else(|| "cubic".to_string());
        let udp = true;

        debug!(
            tag = config.tag,
            server = server,
            port = port,
            mtu = mtu,
            "MASQUE 出站已创建"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server,
            port,
            private_key_pem,
            public_key_der,
            local_ipv4,
            local_ipv6,
            uri,
            sni,
            mtu,
            congestion,
            udp,
            tunnel: Mutex::new(None),
        })
    }

    /// 确保隧道已建立
    async fn ensure_tunnel(&self) -> Result<SharedStack> {
        let mut tunnel_guard = self.tunnel.lock().await;

        // 检查现有隧道是否仍然活跃
        if let Some(ref state) = *tunnel_guard {
            if !state._tunnel_task.is_finished() {
                return Ok(state.stack.clone());
            }
            debug!(tag = self.tag, "MASQUE 隧道已断开，重新连接...");
        }

        // 建立新隧道
        let state = self.create_tunnel().await?;
        let stack = state.stack.clone();
        *tunnel_guard = Some(state);
        Ok(stack)
    }

    /// 创建 MASQUE 隧道
    async fn create_tunnel(&self) -> Result<TunnelState> {
        // 1. 准备 TLS 配置
        let tls_config =
            tls::prepare_tls_config(&self.private_key_pem, &self.public_key_der, &self.sni)?;

        // 2. 建立 QUIC 连接
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(30)));
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.initial_mtu(1242);

        // 拥塞控制
        match self.congestion.as_str() {
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
            "new_reno" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            _ => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::CubicConfig::default(),
                ));
            }
        }

        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        // 解析服务器地址
        let server_addr: SocketAddr = {
            let addr_string = format!("{}:{}", self.server, self.port);
            tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                addr_string.to_socket_addrs()
            })
            .await??
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("无法解析 MASQUE 服务器: {}:{}", self.server, self.port)
            })?
        };

        let quic_conn = endpoint.connect(server_addr, &self.sni)?.await?;
        debug!(tag = self.tag, server = %server_addr, "MASQUE QUIC 连接已建立");

        // 3. 创建 smoltcp 用户态网络栈
        let local_ip = self
            .local_ipv4
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)));
        let stack = stack::create_stack(local_ip, self.mtu);

        // 4. 通过 QUIC datagram 进行 IP 包隧道传输
        let stack_clone = stack.clone();
        let conn_clone = quic_conn.clone();
        let tag = self.tag.clone();
        let tunnel_task = tokio::spawn(async move {
            Self::tunnel_loop(stack_clone, conn_clone, tag).await;
        });

        Ok(TunnelState {
            stack,
            quic_conn,
            _tunnel_task: tunnel_task,
        })
    }

    /// 隧道主循环：bidirectional IP packet forwarding
    ///
    /// - 从 smoltcp 取出站 IP 包 → 编码为 CONNECT-IP datagram → 通过 QUIC datagram 发送
    /// - 从 QUIC datagram 接收 → 解码 CONNECT-IP datagram → 注入 smoltcp
    async fn tunnel_loop(stack: SharedStack, conn: quinn::Connection, tag: String) {
        let conn_send = conn.clone();
        let stack_send = stack.clone();

        // 出站 IP 包发送循环
        let tag_send = tag.clone();
        let send_task = tokio::spawn(async move {
            loop {
                let packet = {
                    let mut s = stack_send.lock().unwrap();
                    s.poll();
                    s.take_outbound_packet()
                };

                if let Some(pkt) = packet {
                    let datagram = encode_ip_datagram(&pkt);
                    if let Err(e) = conn_send.send_datagram(Bytes::from(datagram.to_vec())) {
                        warn!(tag = tag_send, error = %e, "MASQUE 发送 IP datagram 失败");
                        break;
                    }
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        });

        // 入站 IP 包接收循环
        let stack_recv = stack;
        let tag_recv = tag.clone();
        let recv_task = tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(datagram) => match decode_ip_datagram(&datagram) {
                        Ok((0, ip_packet)) => {
                            let mut s = stack_recv.lock().unwrap();
                            s.inject_packet(ip_packet.to_vec());
                            s.poll();
                        }
                        Ok((ctx, _)) => {
                            debug!(tag = tag_recv, ctx = ctx, "忽略非 IP context 的 datagram");
                        }
                        Err(e) => {
                            warn!(tag = tag_recv, error = %e, "解码 CONNECT-IP datagram 失败");
                        }
                    },
                    Err(e) => {
                        error!(tag = tag_recv, error = %e, "MASQUE QUIC datagram 接收失败");
                        break;
                    }
                }
            }
        });

        // 等待任一任务结束
        tokio::select! {
            _ = send_task => {},
            _ = recv_task => {},
        }
    }
}

#[async_trait]
impl OutboundHandler for MasqueOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let stack = self.ensure_tunnel().await?;

        // 解析目标地址
        let remote_addr: SocketAddr = match &session.target {
            Address::Ip(addr) => *addr,
            Address::Domain(host, port) => {
                let host_owned = host.clone();
                let port_val = *port;
                tokio::task::spawn_blocking(move || {
                    use std::net::ToSocketAddrs;
                    format!("{}:{}", host_owned, port_val).to_socket_addrs()
                })
                .await??
                .next()
                .ok_or_else(|| anyhow::anyhow!("无法解析目标地址: {}:{}", host, port))?
            }
        };

        // 通过 smoltcp 建立 TCP 连接
        let tcp_stream = stack::StackTcpStream::new(stack, remote_addr)?;

        // 等待 TCP 连接建立（轮询 smoltcp 直到连接就绪）
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            {
                let mut s = tcp_stream.stack.lock().unwrap();
                s.poll();
                if s.tcp_may_send(tcp_stream.handle) {
                    break;
                }
                if !s.tcp_is_active(tcp_stream.handle) {
                    anyhow::bail!("MASQUE TCP 连接到 {} 失败", remote_addr);
                }
            }
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!("MASQUE TCP 连接到 {} 超时", remote_addr);
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        debug!(target = %session.target, "MASQUE TCP 连接已建立");
        Ok(Box::new(tcp_stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        // MASQUE 支持 UDP，但需要通过 smoltcp UDP socket
        // 目前返回不支持，后续可扩展
        anyhow::bail!("MASQUE UDP 转发暂不支持（需 smoltcp UDP socket 集成）")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn test_masque_config_missing_fields() {
        let config = OutboundConfig {
            tag: "masque-test".to_string(),
            protocol: "masque".to_string(),
            settings: OutboundSettings::default(),
        };
        // 缺少 address，应该失败
        assert!(MasqueOutbound::new(&config).is_err());
    }

    #[test]
    fn test_masque_config_with_keys() {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD;

        let config = OutboundConfig {
            tag: "masque-test".to_string(),
            protocol: "masque".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(443),
                private_key: Some(enc.encode(b"test-private-key-der")),
                public_key: Some(enc.encode(b"test-public-key-der")),
                sni: Some("test.example.com".to_string()),
                local_address: Some("172.16.0.2".to_string()),
                mtu: Some(1280),
                ..Default::default()
            },
        };

        let outbound = MasqueOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag, "masque-test");
        assert_eq!(outbound.server, "127.0.0.1");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "test.example.com");
        assert_eq!(outbound.mtu, 1280);
        assert!(outbound.local_ipv4.is_some());
    }

    #[test]
    fn test_masque_default_values() {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD;

        let config = OutboundConfig {
            tag: "masque-default".to_string(),
            protocol: "masque".to_string(),
            settings: OutboundSettings {
                address: Some("warp.example.com".to_string()),
                port: Some(443),
                private_key: Some(enc.encode(b"key")),
                public_key: Some(enc.encode(b"pub")),
                ..Default::default()
            },
        };

        let outbound = MasqueOutbound::new(&config).unwrap();
        assert_eq!(outbound.sni, DEFAULT_CONNECT_SNI);
        assert_eq!(outbound.mtu, 1280);
        assert_eq!(outbound.congestion, "cubic");
    }
}
