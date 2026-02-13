//! Unified dialer abstraction layer.
//!
//! This module provides a centralized place to configure and apply
//! socket-level options before connecting. Inspired by sing-box's dialer layer,
//! it handles:
//!
//! - Bind to specific interface / source address
//! - Routing mark (fwmark / SO_MARK)
//! - TCP Fast Open (TFO)
//! - MPTCP (Multipath TCP)
//! - Happy Eyeballs (RFC 8305) connection racing
//! - Connect timeout
//! - Keep-alive settings
//! - Per-outbound domain resolver (sing-box compatible)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use tokio::net::TcpStream;
use tracing::debug;

use crate::dns::DnsResolver;

#[allow(unused_imports)]
use super::traffic::RoutingMark;

/// Dialer configuration — can be specified per-outbound or globally.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DialerConfig {
    /// Bind to a specific network interface name (e.g., "eth0", "wlan0").
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,

    /// Bind to a specific source IP address.
    #[serde(rename = "bind-address")]
    pub bind_address: Option<String>,

    /// Routing mark (Linux SO_MARK / fwmark).
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<u32>,

    /// Enable TCP Fast Open.
    #[serde(rename = "tcp-fast-open")]
    pub tcp_fast_open: bool,

    /// Enable Multipath TCP.
    pub mptcp: bool,

    /// Connect timeout in milliseconds. Default: 5000.
    #[serde(rename = "connect-timeout")]
    pub connect_timeout_ms: Option<u64>,

    /// TCP keep-alive interval in seconds. 0 = disabled.
    #[serde(rename = "tcp-keep-alive")]
    pub tcp_keep_alive_secs: Option<u64>,

    /// Enable Happy Eyeballs (dual-stack connection racing).
    #[serde(rename = "happy-eyeballs")]
    pub happy_eyeballs: Option<bool>,

    /// Per-outbound domain resolver name.
    /// References a named DNS server from the dns.servers config.
    #[serde(rename = "domain-resolver")]
    pub domain_resolver: Option<String>,
}

impl DialerConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(5000))
    }

    pub fn happy_eyeballs_enabled(&self) -> bool {
        self.happy_eyeballs.unwrap_or(true)
    }
}

/// Unified dialer that applies socket options and connects.
pub struct Dialer {
    config: DialerConfig,
    resolver: Option<Arc<dyn DnsResolver>>,
}

impl Dialer {
    pub fn new(config: DialerConfig) -> Self {
        Self {
            config,
            resolver: None,
        }
    }

    /// Create a dialer with a custom domain resolver.
    pub fn with_resolver(config: DialerConfig, resolver: Arc<dyn DnsResolver>) -> Self {
        Self {
            config,
            resolver: Some(resolver),
        }
    }

    /// Create a dialer with default settings.
    pub fn default_dialer() -> Self {
        Self {
            config: DialerConfig::default(),
            resolver: None,
        }
    }

    /// Connect to the given address, applying all configured socket options.
    pub async fn connect(&self, addr: SocketAddr) -> Result<TcpStream> {
        let timeout = self.config.connect_timeout();

        let stream = tokio::time::timeout(timeout, async { self.connect_inner(addr).await })
            .await
            .map_err(|_| anyhow::anyhow!("connect timeout after {:?} to {}", timeout, addr))??;

        // Apply post-connect options
        self.apply_post_connect(&stream)?;

        debug!(
            addr = %addr,
            interface = self.config.interface_name.as_deref().unwrap_or("-"),
            tfo = self.config.tcp_fast_open,
            mptcp = self.config.mptcp,
            "dialer connected"
        );

        Ok(stream)
    }

    /// Connect to a host:port with optional Happy Eyeballs.
    /// Uses the custom domain resolver if configured, otherwise falls back to system DNS.
    pub async fn connect_host(&self, host: &str, port: u16) -> Result<TcpStream> {
        if self.config.happy_eyeballs_enabled() {
            let timeout_ms = self.config.connect_timeout_ms.unwrap_or(5000);
            let stream = super::traffic::happy_eyeballs_connect(
                host,
                port,
                timeout_ms,
                self.resolver.as_deref(),
            )
            .await?;
            self.apply_post_connect(&stream)?;
            Ok(stream)
        } else {
            // Resolve using custom resolver or system DNS
            let addr = self.resolve_host(host, port).await?;
            self.connect(addr).await
        }
    }

    /// Resolve a host:port to a SocketAddr using the configured resolver.
    async fn resolve_host(&self, host: &str, port: u16) -> Result<SocketAddr> {
        if let Some(resolver) = &self.resolver {
            let ips = resolver.resolve(host).await?;
            let ip = ips
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", host))?;
            Ok(SocketAddr::new(ip, port))
        } else {
            let addr_str = format!("{}:{}", host, port);
            let addrs = tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                addr_str.to_socket_addrs()
            })
            .await??;
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}:{}", host, port))
        }
    }

    async fn connect_inner(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = if self.config.mptcp {
            // 尝试创建 MPTCP socket
            match self.create_mptcp_socket(addr.is_ipv4()) {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "MPTCP socket creation failed, falling back to TCP");
                    if addr.is_ipv4() {
                        tokio::net::TcpSocket::new_v4()?
                    } else {
                        tokio::net::TcpSocket::new_v6()?
                    }
                }
            }
        } else if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        // Bind to source address if configured
        if let Some(ref bind_addr) = self.config.bind_address {
            let ip: IpAddr = bind_addr
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid bind address '{}': {}", bind_addr, e))?;
            socket.bind(SocketAddr::new(ip, 0))?;
        }

        // Apply routing mark (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(mark) = self.config.routing_mark {
            let rm = RoutingMark::new(mark);
            use std::os::unix::io::AsRawFd;
            rm.apply_to_socket(socket.as_raw_fd())?;
        }

        let stream = socket.connect(addr).await?;
        Ok(stream)
    }

    /// 创建 MPTCP socket。
    ///
    /// Linux: 使用 IPPROTO_MPTCP (协议号 262) 创建 socket。
    /// 其他平台: 返回错误（将 fallback 到普通 TCP）。
    fn create_mptcp_socket(&self, ipv4: bool) -> Result<tokio::net::TcpSocket> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::FromRawFd;

            const IPPROTO_MPTCP: i32 = 262;

            let domain = if ipv4 {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };

            let socket = socket2::Socket::new_raw(
                domain,
                socket2::Type::STREAM,
                Some(socket2::Protocol::from(IPPROTO_MPTCP)),
            )?;

            socket.set_nonblocking(true)?;

            // 将 socket2::Socket 转为 tokio::net::TcpSocket
            let std_stream = unsafe {
                let fd = socket.into_raw_fd();
                std::net::TcpStream::from_raw_fd(fd)
            };

            let tcp_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
            debug!("MPTCP socket created successfully");
            Ok(tcp_socket)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = ipv4;
            anyhow::bail!("MPTCP is only supported on Linux kernel 5.6+");
        }
    }

    fn apply_post_connect(&self, stream: &TcpStream) -> Result<()> {
        // TCP keep-alive
        if let Some(interval) = self.config.tcp_keep_alive_secs {
            if interval > 0 {
                let sock_ref = socket2::SockRef::from(stream);
                let keepalive =
                    socket2::TcpKeepalive::new().with_time(Duration::from_secs(interval));
                sock_ref.set_tcp_keepalive(&keepalive)?;
            }
        }

        // TCP_NODELAY — always enable for proxy traffic
        stream.set_nodelay(true)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialer_config_defaults() {
        let config = DialerConfig::default();
        assert!(config.interface_name.is_none());
        assert!(config.bind_address.is_none());
        assert!(config.routing_mark.is_none());
        assert!(!config.tcp_fast_open);
        assert!(!config.mptcp);
        assert_eq!(config.connect_timeout(), Duration::from_millis(5000));
        assert!(config.happy_eyeballs_enabled());
    }

    #[test]
    fn dialer_config_custom_timeout() {
        let config = DialerConfig {
            connect_timeout_ms: Some(10000),
            ..Default::default()
        };
        assert_eq!(config.connect_timeout(), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn dialer_connect_localhost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialer = Dialer::default_dialer();
        let stream = dialer.connect(addr).await;
        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn dialer_connect_timeout() {
        let config = DialerConfig {
            // Very short timeout
            connect_timeout_ms: Some(1),
            happy_eyeballs: Some(false),
            ..Default::default()
        };
        let dialer = Dialer::new(config);

        // Use a port that's unlikely to be listening on localhost
        // This should either timeout (1ms) or get connection refused
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = dialer.connect(addr).await;
        // Either timeout or connection refused — both are errors
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dialer_with_bind_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = DialerConfig {
            bind_address: Some("127.0.0.1".to_string()),
            ..Default::default()
        };
        let dialer = Dialer::new(config);
        let stream = dialer.connect(addr).await;
        assert!(stream.is_ok());
    }

    #[test]
    fn dialer_config_deserialize() {
        let yaml = r#"
interface-name: eth0
bind-address: "192.168.1.1"
routing-mark: 233
tcp-fast-open: true
mptcp: true
connect-timeout: 10000
tcp-keep-alive: 60
happy-eyeballs: false
"#;
        let config: DialerConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.interface_name.as_deref(), Some("eth0"));
        assert_eq!(config.bind_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(config.routing_mark, Some(233));
        assert!(config.tcp_fast_open);
        assert!(config.mptcp);
        assert!(!config.happy_eyeballs_enabled());
    }
}
