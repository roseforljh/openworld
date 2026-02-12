use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::ffi::c_void;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::InboundConfig;
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

/// Redirect 入站 (Linux iptables REDIRECT)
///
/// 通过 iptables REDIRECT 规则将流量重定向到本地端口。
/// 使用 SO_ORIGINAL_DST 获取原始目标地址。
pub struct RedirectInbound {
    tag: String,
}

impl RedirectInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        Ok(Self {
            tag: config.tag.clone(),
        })
    }
}

#[async_trait]
impl InboundHandler for RedirectInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let original_dst = get_original_dst(&stream)?;

        debug!(
            tag = self.tag,
            source = %source,
            dest = %original_dst,
            "redirect inbound connection"
        );

        let session = Session {
            target: Address::Ip(original_dst),
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network: Network::Tcp,
            sniff: true,
            detected_protocol: None,
        };

        Ok(InboundResult {
            session,
            stream,
            udp_transport: None,
        })
    }
}

/// TProxy 入站 (Linux TPROXY)
///
/// 使用 iptables TPROXY 规则实现透明代理。
/// 与 Redirect 不同，TProxy 可以处理 TCP 和 UDP。
pub struct TProxyInbound {
    tag: String,
    network: Network,
}

impl TProxyInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let network = match config.settings.network.as_deref() {
            Some("udp") => Network::Udp,
            _ => Network::Tcp,
        };
        Ok(Self {
            tag: config.tag.clone(),
            network,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

#[async_trait]
impl InboundHandler for TProxyInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let original_dst = get_original_dst(&stream)?;

        debug!(
            tag = self.tag,
            source = %source,
            dest = %original_dst,
            network = ?self.network,
            "tproxy inbound connection"
        );

        let session = Session {
            target: Address::Ip(original_dst),
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network: self.network,
            sniff: true,
            detected_protocol: None,
        };

        Ok(InboundResult {
            session,
            stream,
            udp_transport: None,
        })
    }
}

fn get_original_dst(stream: &ProxyStream) -> Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        return get_original_dst_linux(stream);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        anyhow::bail!("transparent proxy inbound is Linux-only (SO_ORIGINAL_DST/IP_TRANSPARENT)");
    }
}

#[cfg(target_os = "linux")]
fn get_original_dst_linux(stream: &ProxyStream) -> Result<SocketAddr> {
    let tcp_stream = stream
        .as_ref()
        .as_any()
        .downcast_ref::<tokio::net::TcpStream>()
        .ok_or_else(|| anyhow::anyhow!("transparent inbound requires tokio::net::TcpStream"))?;

    let fd = tcp_stream.as_raw_fd();
    let mut addr: SockAddrIn = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<SockAddrIn>() as SockLenT;

    let ret = unsafe {
        getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut SockAddrIn).cast::<c_void>(),
            &mut addr_len,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(err).context("getsockopt(SO_ORIGINAL_DST) failed");
    }

    if addr_len < std::mem::size_of::<SockAddrIn>() as SockLenT {
        anyhow::bail!("getsockopt(SO_ORIGINAL_DST) returned short sockaddr");
    }

    if addr.sin_family != AF_INET {
        anyhow::bail!(
            "SO_ORIGINAL_DST returned unsupported address family: {}",
            addr.sin_family
        );
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

#[cfg(target_os = "linux")]
type SockLenT = u32;

#[cfg(target_os = "linux")]
const SOL_IP: i32 = 0;
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: i32 = 80;
#[cfg(target_os = "linux")]
const AF_INET: u16 = 2;

#[cfg(target_os = "linux")]
#[repr(C)]
struct InAddr {
    s_addr: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: InAddr,
    sin_zero: [u8; 8],
}

#[cfg(target_os = "linux")]
extern "C" {
    fn getsockopt(
        socket: i32,
        level: i32,
        option_name: i32,
        option_value: *mut c_void,
        option_len: *mut SockLenT,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::InboundSettings;

    #[test]
    fn redirect_inbound_creation() {
        let config = InboundConfig {
            tag: "redirect-in".to_string(),
            protocol: "redirect".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 7893,
            sniffing: Default::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        };
        let inbound = RedirectInbound::new(&config).unwrap();
        assert_eq!(inbound.tag(), "redirect-in");
    }

    #[test]
    fn tproxy_inbound_tcp() {
        let config = InboundConfig {
            tag: "tproxy-in".to_string(),
            protocol: "tproxy".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 7894,
            sniffing: Default::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        };
        let inbound = TProxyInbound::new(&config).unwrap();
        assert_eq!(inbound.tag(), "tproxy-in");
        assert_eq!(inbound.network(), Network::Tcp);
    }

    #[test]
    fn tproxy_inbound_udp() {
        let config = InboundConfig {
            tag: "tproxy-udp".to_string(),
            protocol: "tproxy".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 7895,
            sniffing: Default::default(),
            settings: InboundSettings {
                network: Some("udp".to_string()),
                ..Default::default()
            },
            max_connections: None,
        };
        let inbound = TProxyInbound::new(&config).unwrap();
        assert_eq!(inbound.network(), Network::Udp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_original_dst_requires_tcp_stream() {
        let (duplex, _peer) = tokio::io::duplex(64);
        let stream: ProxyStream = Box::new(duplex);
        let err = get_original_dst(&stream).unwrap_err();
        assert!(err.to_string().contains("tokio::net::TcpStream"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn get_original_dst_reports_linux_only() {
        let (duplex, _peer) = tokio::io::duplex(64);
        let stream: ProxyStream = Box::new(duplex);
        let err = get_original_dst(&stream).unwrap_err();
        assert!(err.to_string().contains("Linux-only"));
    }
}
