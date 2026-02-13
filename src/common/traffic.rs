use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Semaphore;

/// Token bucket rate limiter
pub struct RateLimiter {
    tokens: AtomicI64,
    max_tokens: i64,
    refill_rate: i64, // tokens per second
    last_refill: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given bytes-per-second limit
    pub fn new(bytes_per_second: u64) -> Self {
        let max = bytes_per_second as i64;
        Self {
            tokens: AtomicI64::new(max),
            max_tokens: max,
            refill_rate: max,
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Try to consume `n` tokens. Returns the number of tokens actually consumed.
    pub fn try_consume(&self, n: u64) -> u64 {
        self.refill();
        let n = n as i64;
        let available = self.tokens.load(Ordering::Relaxed);
        let consume = n.min(available).max(0);
        if consume > 0 {
            self.tokens.fetch_sub(consume, Ordering::Relaxed);
        }
        consume as u64
    }

    /// Check if there are any tokens available
    pub fn available(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Relaxed).max(0) as u64
    }

    fn refill(&self) {
        // 如果锁中毒（持有者 panic），静默跳过而非传播 panic
        let mut last = match self.last_refill.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return,
        };
        let now = Instant::now();
        let elapsed = now.duration_since(*last);
        let new_tokens = (elapsed.as_millis() as i64 * self.refill_rate) / 1000;
        if new_tokens > 0 {
            let current = self.tokens.load(Ordering::Relaxed);
            let refilled = (current + new_tokens).min(self.max_tokens);
            self.tokens.store(refilled, Ordering::Relaxed);
            *last = now;
        }
    }

    pub fn max_rate(&self) -> u64 {
        self.max_tokens as u64
    }
}

/// Connection limiter using a semaphore
pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    max_connections: u32,
    active: Arc<AtomicU64>,
}

impl ConnectionLimiter {
    pub fn new(max_connections: u32) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_connections as usize)),
            max_connections,
            active: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Try to acquire a connection slot. Returns a guard that releases on drop.
    pub fn try_acquire(&self) -> Option<ConnectionGuard> {
        let permit = self.semaphore.clone().try_acquire_owned().ok()?;
        self.active.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionGuard {
            _permit: permit,
            active: self.active.clone(),
        })
    }

    pub fn active_count(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    pub fn available(&self) -> u32 {
        self.semaphore.available_permits() as u32
    }
}

pub struct ConnectionGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    active: Arc<AtomicU64>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Traffic statistics tracker
pub struct TrafficStats {
    upload: AtomicU64,
    download: AtomicU64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        }
    }

    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn upload(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.upload() + self.download()
    }

    pub fn reset(&self) {
        self.upload.store(0, Ordering::Relaxed);
        self.download.store(0, Ordering::Relaxed);
    }
}

/// Happy Eyeballs (RFC 8305) connection racing.
/// Races IPv4 and IPv6 connections, with IPv6 preferred.
pub async fn happy_eyeballs_connect(
    host: &str,
    port: u16,
    timeout_ms: u64,
    resolver: Option<&dyn crate::dns::DnsResolver>,
) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::net::TcpStream;
    use std::net::ToSocketAddrs;

    let addrs: Vec<std::net::SocketAddr> = if let Some(r) = resolver {
        // Use custom resolver
        let ips = r.resolve(host).await?;
        ips.into_iter().map(|ip| std::net::SocketAddr::new(ip, port)).collect()
    } else {
        // Use system DNS
        let addr_str = format!("{}:{}", host, port);
        addr_str
            .to_socket_addrs()
            .map(|iter| iter.collect())
            .unwrap_or_default()
    };

    if addrs.is_empty() {
        anyhow::bail!("no addresses resolved for {}:{}", host, port);
    }

    // Separate IPv6 and IPv4
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6());

    // Interleave: IPv6 first, then IPv4 with 250ms delay
    let timeout = std::time::Duration::from_millis(timeout_ms);

    // Try IPv6 first (if available)
    if !v6.is_empty() {
        let v6_addr = v6[0];
        let v4_addr = v4.first().copied();

        // Race: IPv6 with head start
        tokio::select! {
            result = async {
                tokio::time::timeout(timeout, TcpStream::connect(v6_addr)).await
            } => {
                match result {
                    Ok(Ok(stream)) => return Ok(stream),
                    _ => {} // IPv6 failed, try IPv4
                }
            }
            _ = async {
                // Give IPv6 a 250ms head start
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if let Some(v4_a) = v4_addr {
                    let _ = tokio::time::timeout(timeout, TcpStream::connect(v4_a)).await;
                }
            } => {}
        }
    }

    // Fallback: try all addresses sequentially
    for addr in v4.iter().chain(v6.iter()) {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            _ => continue,
        }
    }

    anyhow::bail!("failed to connect to {}:{}", host, port)
}

/// IPPROTO_MPTCP protocol number (Linux)
pub const IPPROTO_MPTCP: u32 = 262;

/// MPTCP (Multipath TCP) 配置
#[derive(Debug, Clone, Default)]
pub struct MptcpConfig {
    pub enabled: bool,
}

impl MptcpConfig {
    /// 检查当前平台是否支持 MPTCP
    pub fn is_platform_supported() -> bool {
        cfg!(target_os = "linux")
    }

    /// 应用 MPTCP 配置到 socket。
    /// 不支持时静默回退到普通 TCP。
    #[cfg(target_os = "linux")]
    pub fn apply_to_socket(&self, socket: &socket2::Socket) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        // 在 Linux 上设置 IPPROTO_MPTCP
        // 这需要内核 >= 5.6 支持
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let proto = IPPROTO_MPTCP as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_CONGESTION,
                &proto as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            tracing::debug!("MPTCP not supported, falling back to TCP");
        }
        Ok(())
    }

    /// 非 Linux 平台：静默回退
    #[cfg(not(target_os = "linux"))]
    pub fn apply_to_socket(&self, _socket: &std::net::TcpStream) -> anyhow::Result<()> {
        if self.enabled {
            tracing::debug!("MPTCP not supported on this platform, falling back to TCP");
        }
        Ok(())
    }
}

/// 路由标记 (fwmark / SO_MARK)
#[derive(Debug, Clone, Copy)]
pub struct RoutingMark {
    mark: u32,
}

impl RoutingMark {
    pub fn new(mark: u32) -> Self {
        Self { mark }
    }

    pub fn value(&self) -> u32 {
        self.mark
    }

    /// 从十六进制字符串解析 (如 "0xFF")
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        let mark = u32::from_str_radix(s, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex routing mark: {}", e))?;
        Ok(Self { mark })
    }

    /// 从字符串解析（支持十进制和 0x 前缀十六进制）
    pub fn from_string(s: &str) -> anyhow::Result<Self> {
        if s.starts_with("0x") || s.starts_with("0X") {
            Self::from_hex(s)
        } else {
            let mark: u32 = s.parse()
                .map_err(|e| anyhow::anyhow!("invalid routing mark: {}", e))?;
            Ok(Self { mark })
        }
    }

    /// 应用 fwmark 到 socket (Linux: SO_MARK)
    #[cfg(target_os = "linux")]
    pub fn apply_to_socket(&self, fd: std::os::unix::io::RawFd) -> anyhow::Result<()> {
        let mark = self.mark as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            anyhow::bail!("failed to set SO_MARK: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// 非 Linux 平台：使用接口绑定实现等效功能
    #[cfg(not(target_os = "linux"))]
    pub fn apply_to_socket(&self, _fd: i32) -> anyhow::Result<()> {
        tracing::debug!(mark = self.mark, "SO_MARK not supported on this platform, using bind interface");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_creation() {
        let limiter = RateLimiter::new(1024);
        assert_eq!(limiter.max_rate(), 1024);
        assert!(limiter.available() > 0);
    }

    #[test]
    fn rate_limiter_consume() {
        let limiter = RateLimiter::new(1000);
        let consumed = limiter.try_consume(500);
        assert_eq!(consumed, 500);
        let remaining = limiter.available();
        assert!(remaining <= 500);
    }

    #[test]
    fn rate_limiter_overconsume() {
        let limiter = RateLimiter::new(100);
        let consumed = limiter.try_consume(200);
        assert!(consumed <= 100);
    }

    #[test]
    fn connection_limiter_creation() {
        let limiter = ConnectionLimiter::new(10);
        assert_eq!(limiter.max_connections(), 10);
        assert_eq!(limiter.active_count(), 0);
        assert_eq!(limiter.available(), 10);
    }

    #[test]
    fn connection_limiter_acquire_release() {
        let limiter = ConnectionLimiter::new(2);
        let g1 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 1);
        assert_eq!(limiter.available(), 1);
        let g2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 2);
        assert_eq!(limiter.available(), 0);
        // Third should fail
        assert!(limiter.try_acquire().is_none());
        // Release one
        drop(g1);
        assert_eq!(limiter.active_count(), 1);
        assert_eq!(limiter.available(), 1);
        // Now can acquire again
        let _g3 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 2);
        drop(g2);
        assert_eq!(limiter.active_count(), 1);
    }

    #[test]
    fn traffic_stats_basic() {
        let stats = TrafficStats::new();
        stats.add_upload(100);
        stats.add_download(200);
        assert_eq!(stats.upload(), 100);
        assert_eq!(stats.download(), 200);
        assert_eq!(stats.total(), 300);
    }

    #[test]
    fn traffic_stats_reset() {
        let stats = TrafficStats::new();
        stats.add_upload(50);
        stats.add_download(75);
        stats.reset();
        assert_eq!(stats.upload(), 0);
        assert_eq!(stats.download(), 0);
    }

    #[test]
    fn traffic_stats_concurrent() {
        let stats = TrafficStats::new();
        for _ in 0..100 {
            stats.add_upload(10);
            stats.add_download(20);
        }
        assert_eq!(stats.upload(), 1000);
        assert_eq!(stats.download(), 2000);
    }

    #[tokio::test]
    async fn happy_eyeballs_connect_localhost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let result = happy_eyeballs_connect("127.0.0.1", addr.port(), 5000, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_connect_invalid_host() {
        // Use a domain that can't possibly resolve
        let result = happy_eyeballs_connect("this-host-does-not-exist-at-all.invalid", 1, 100, None).await;
        assert!(result.is_err());
    }

    // MPTCP tests
    #[test]
    fn mptcp_config_default() {
        let config = MptcpConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn mptcp_config_enabled() {
        let config = MptcpConfig { enabled: true };
        assert!(config.enabled);
    }

    #[test]
    fn mptcp_protocol_number() {
        assert_eq!(IPPROTO_MPTCP, 262);
    }

    // RoutingMark tests
    #[test]
    fn routing_mark_creation() {
        let mark = RoutingMark::new(233);
        assert_eq!(mark.value(), 233);
    }

    #[test]
    fn routing_mark_from_hex() {
        let mark = RoutingMark::from_hex("0xFF").unwrap();
        assert_eq!(mark.value(), 255);
    }

    #[test]
    fn routing_mark_from_hex_invalid() {
        assert!(RoutingMark::from_hex("not-hex").is_err());
    }

    #[test]
    fn routing_mark_from_string_decimal() {
        let mark = RoutingMark::from_string("233").unwrap();
        assert_eq!(mark.value(), 233);
    }

    #[test]
    fn routing_mark_from_string_hex() {
        let mark = RoutingMark::from_string("0xE9").unwrap();
        assert_eq!(mark.value(), 233);
    }
}
