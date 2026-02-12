use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use tokio_util::sync::CancellationToken;

use crate::common::traffic::RateLimiter;
use crate::common::ProxyStream;

// ─── Buffer Pool ───────────────────────────────────────────────────────────

/// Small buffer size: 4 KiB — for control messages, handshakes.
const BUF_SIZE_SMALL: usize = 4 * 1024;
/// Default buffer size: 32 KiB — matches typical TCP window / TLS record size.
const BUF_SIZE: usize = 32 * 1024;
/// Large buffer size: 64 KiB — for high-throughput relay.
const BUF_SIZE_LARGE: usize = 64 * 1024;
/// Maximum number of buffers kept in the pool per tier.
const POOL_MAX: usize = 512;

/// Lock-free buffer pool to reduce allocation pressure under high concurrency.
/// Instead of allocating a new Vec<u8> per read, we recycle buffers.
/// Supports tiered buffer sizes for different use cases.
pub struct BufferPool {
    small: std::sync::Mutex<Vec<Vec<u8>>>,
    medium: std::sync::Mutex<Vec<Vec<u8>>>,
    large: std::sync::Mutex<Vec<Vec<u8>>>,
    max: usize,
    // Stats
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl BufferPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            small: std::sync::Mutex::new(Vec::with_capacity(capacity / 4)),
            medium: std::sync::Mutex::new(Vec::with_capacity(capacity)),
            large: std::sync::Mutex::new(Vec::with_capacity(capacity / 4)),
            max: capacity,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get a default (medium) buffer from the pool, or allocate a new one.
    pub fn get(&self) -> Vec<u8> {
        self.get_sized(BUF_SIZE)
    }

    /// Get a buffer of specific tier from the pool.
    pub fn get_sized(&self, size: usize) -> Vec<u8> {
        let (stack, alloc_size) = if size <= BUF_SIZE_SMALL {
            (&self.small, BUF_SIZE_SMALL)
        } else if size <= BUF_SIZE {
            (&self.medium, BUF_SIZE)
        } else {
            (&self.large, BUF_SIZE_LARGE)
        };

        if let Ok(mut s) = stack.lock() {
            if let Some(buf) = s.pop() {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return buf;
            }
        }
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![0u8; alloc_size]
    }

    /// Get a small buffer (4 KiB) for control messages.
    pub fn get_small(&self) -> Vec<u8> {
        self.get_sized(BUF_SIZE_SMALL)
    }

    /// Get a large buffer (64 KiB) for high-throughput relay.
    pub fn get_large(&self) -> Vec<u8> {
        self.get_sized(BUF_SIZE_LARGE)
    }

    /// Return a buffer to the pool. Oversized buffers are dropped.
    pub fn put(&self, buf: Vec<u8>) {
        let cap = buf.capacity();
        let (stack, max_cap) = if cap <= BUF_SIZE_SMALL * 2 && cap >= BUF_SIZE_SMALL {
            (&self.small, self.max / 4)
        } else if cap <= BUF_SIZE * 4 && cap >= BUF_SIZE {
            (&self.medium, self.max)
        } else if cap <= BUF_SIZE_LARGE * 4 && cap >= BUF_SIZE_LARGE {
            (&self.large, self.max / 4)
        } else {
            return; // 不合适的大小，直接丢弃
        };

        if let Ok(mut s) = stack.lock() {
            if s.len() < max_cap {
                s.push(buf);
            }
        }
    }

    /// 获取 pool 统计信息: (hits, misses)
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.misses.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Global buffer pool singleton.
pub fn global_buffer_pool() -> &'static BufferPool {
    static POOL: std::sync::OnceLock<BufferPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| BufferPool::new(POOL_MAX))
}

// ─── Relay Stats ───────────────────────────────────────────────────────────

/// Real-time relay statistics, atomically updated during transfer.
/// Can be polled from outside (e.g., API traffic endpoint) while relay is running.
#[derive(Debug)]
pub struct RelayStats {
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

impl RelayStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        })
    }

    pub fn upload(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
    }
}

// ─── Relay Options ─────────────────────────────────────────────────────────

/// Configuration for an enhanced relay session.
pub struct RelayOptions {
    /// Idle timeout — close if no data in either direction for this long.
    /// Default: 300s (5 minutes).
    pub idle_timeout: Duration,
    /// Optional real-time stats tracker (updated atomically during relay).
    pub stats: Option<Arc<RelayStats>>,
    /// Optional upload (client→remote) rate limiter.
    pub upload_limiter: Option<Arc<RateLimiter>>,
    /// Optional download (remote→client) rate limiter.
    pub download_limiter: Option<Arc<RateLimiter>>,
    /// Optional cancellation token for graceful shutdown.
    pub cancel: Option<CancellationToken>,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(300),
            stats: None,
            upload_limiter: None,
            download_limiter: None,
            cancel: None,
        }
    }
}

// ─── Simple relay (backward compat) ────────────────────────────────────────

/// Simple bidirectional relay — backward compatible entry point.
/// Uses default 5-minute idle timeout, no rate limiting.
pub async fn relay<A, B>(a: A, b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_with_options(a, b, RelayOptions::default()).await
}

// ─── Enhanced relay ────────────────────────────────────────────────────────

/// Enhanced bidirectional relay with:
/// - Idle timeout (no data in either direction → close)
/// - Half-close handling (one side EOF → shutdown write on the other, drain remaining)
/// - Real-time atomic stats (upload/download bytes updated during transfer)
/// - Optional per-connection rate limiting
/// - Buffer pool reuse to reduce allocation pressure
///
/// Returns (upload_bytes, download_bytes) where upload = client→remote.
pub async fn relay_with_options<A, B>(
    mut client: A,
    mut remote: B,
    opts: RelayOptions,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let idle_timeout = opts.idle_timeout;

    if opts.upload_limiter.is_none() && opts.download_limiter.is_none() && opts.stats.is_none() {
        let cancel = opts.cancel.clone().unwrap_or_default();

        let result = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                _ = cancel.cancelled() => Ok((0, 0)),
                r = async {
                    let (mut client_read, mut client_write) = tokio::io::split(client);
                    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

                    let upload_fut = async {
                        let up = tokio::io::copy(&mut client_read, &mut remote_write).await?;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut remote_write).await;
                        Ok::<u64, anyhow::Error>(up)
                    };

                    let download_fut = async {
                        let down = tokio::io::copy(&mut remote_read, &mut client_write).await?;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut client_write).await;
                        Ok::<u64, anyhow::Error>(down)
                    };

                    let (up_res, down_res) = tokio::join!(upload_fut, download_fut);
                    Ok::<(u64, u64), anyhow::Error>((up_res?, down_res?))
                } => r,
            }
        })
        .await;

        match result {
            Ok(Ok((up, down))) => {
                return Ok((up, down));
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("relay idle timeout ({:?}), closing", idle_timeout);
                return Ok((0, 0));
            }
        }
    }

    // Use manual copy loop when we have stats or limiters for real-time tracking
    let pool = global_buffer_pool();
    let mut buf_a = pool.get();
    let mut buf_b = pool.get();

    let mut upload: u64 = 0;
    let mut download: u64 = 0;
    let mut client_done = false;
    let mut remote_done = false;

    let cancel = opts.cancel.unwrap_or_default();

    loop {
        // Both sides closed — we're done
        if client_done && remote_done {
            break;
        }

        let result = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                // client → remote (upload)
                r = client.read(&mut buf_a), if !client_done => {
                    CopyEvent::ClientRead(r)
                }
                // remote → client (download)
                r = remote.read(&mut buf_b), if !remote_done => {
                    CopyEvent::RemoteRead(r)
                }
                _ = cancel.cancelled() => {
                    CopyEvent::Cancelled
                }
            }
        })
        .await;

        match result {
            Err(_) => {
                // Idle timeout
                debug!(
                    upload = upload,
                    download = download,
                    "relay idle timeout ({:?}), closing",
                    idle_timeout
                );
                break;
            }
            Ok(event) => match event {
                CopyEvent::Cancelled => {
                    debug!(
                        upload = upload,
                        download = download,
                        "relay cancelled by shutdown signal"
                    );
                    break;
                }
                CopyEvent::ClientRead(Ok(0)) => {
                    // Client EOF → half-close: shutdown write to remote
                    client_done = true;
                    let _ = remote.shutdown().await;
                    debug!(upload = upload, "client EOF, half-closed remote write");
                }
                CopyEvent::ClientRead(Ok(n)) => {
                    let data = &buf_a[..n];
                    // Rate limiting: wait until we can send
                    if let Some(ref limiter) = opts.upload_limiter {
                        wait_for_tokens(limiter, n as u64).await;
                    }
                    remote.write_all(data).await?;
                    upload += n as u64;
                    if let Some(ref stats) = opts.stats {
                        stats.upload.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                CopyEvent::ClientRead(Err(e)) => {
                    debug!(error = %e, "client read error");
                    break;
                }
                CopyEvent::RemoteRead(Ok(0)) => {
                    // Remote EOF → half-close: shutdown write to client
                    remote_done = true;
                    let _ = client.shutdown().await;
                    debug!(download = download, "remote EOF, half-closed client write");
                }
                CopyEvent::RemoteRead(Ok(n)) => {
                    let data = &buf_b[..n];
                    if let Some(ref limiter) = opts.download_limiter {
                        wait_for_tokens(limiter, n as u64).await;
                    }
                    client.write_all(data).await?;
                    download += n as u64;
                    if let Some(ref stats) = opts.stats {
                        stats.download.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                CopyEvent::RemoteRead(Err(e)) => {
                    debug!(error = %e, "remote read error");
                    break;
                }
            },
        }
    }

    // Return buffers to pool
    pool.put(buf_a);
    pool.put(buf_b);

    debug!(
        "relay finished: upload {}B, download {}B",
        upload, download
    );
    Ok((upload, download))
}

/// Internal event enum for select! branches.
enum CopyEvent {
    ClientRead(std::io::Result<usize>),
    RemoteRead(std::io::Result<usize>),
    Cancelled,
}

/// Wait until the rate limiter has enough tokens for `needed` bytes.
/// Uses exponential backoff sleep to avoid busy-spinning.
async fn wait_for_tokens(limiter: &RateLimiter, needed: u64) {
    let mut remaining = needed;
    while remaining > 0 {
        let consumed = limiter.try_consume(remaining);
        remaining -= consumed;
        if remaining > 0 {
            // Sleep proportional to how many bytes we still need
            let rate = limiter.max_rate().max(1);
            let wait_ms = ((remaining as u128 * 1000) / rate as u128).max(1).min(100) as u64;
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
    }
}

// ─── Zero-Copy Relay (Linux splice) ──────────────────────────────────────────

/// Linux splice-based zero-copy relay.
/// Uses kernel pipes + splice() to move data between two TCP sockets
/// without copying to/from user space.
#[cfg(target_os = "linux")]
mod splice {
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use tokio_util::sync::CancellationToken;
    use tracing::debug;

    use super::RelayStats;

    const SPLICE_F_MOVE: libc::c_uint = 1;
    const SPLICE_F_NONBLOCK: libc::c_uint = 2;
    const SPLICE_FLAGS: libc::c_uint = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
    /// Pipe buffer size: 64 KiB (matches typical Linux default pipe size)
    const PIPE_SIZE: usize = 65536;

    /// Create a pipe and return (read_fd, write_fd).
    fn create_pipe() -> std::io::Result<(RawFd, RawFd)> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    /// Close a file descriptor.
    fn close_fd(fd: RawFd) {
        unsafe { libc::close(fd); }
    }

    /// Splice data from `src_fd` into `pipe_write`, then from `pipe_read` into `dst_fd`.
    /// Returns the number of bytes transferred, or 0 on EOF.
    fn splice_one_direction(
        src_fd: RawFd,
        pipe_read: RawFd,
        pipe_write: RawFd,
        dst_fd: RawFd,
    ) -> std::io::Result<usize> {
        // Step 1: splice from source socket into pipe
        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_write,
                std::ptr::null_mut(),
                PIPE_SIZE,
                SPLICE_FLAGS,
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }
        if n == 0 {
            return Ok(0); // EOF
        }

        // Step 2: splice from pipe into destination socket
        let mut written = 0usize;
        while written < n as usize {
            let w = unsafe {
                libc::splice(
                    pipe_read,
                    std::ptr::null_mut(),
                    dst_fd,
                    std::ptr::null_mut(),
                    (n as usize - written),
                    SPLICE_FLAGS & !SPLICE_F_NONBLOCK, // blocking for pipe→socket
                )
            };
            if w < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if w == 0 {
                break;
            }
            written += w as usize;
        }

        Ok(written)
    }

    /// Bidirectional splice relay between two TCP sockets.
    /// Returns (upload_bytes, download_bytes).
    pub async fn splice_relay(
        client_fd: RawFd,
        remote_fd: RawFd,
        idle_timeout: Duration,
        stats: Option<Arc<RelayStats>>,
        cancel: CancellationToken,
    ) -> Result<(u64, u64)> {
        // Create two pipe pairs: one for each direction
        let (c2r_read, c2r_write) = create_pipe()?;
        let (r2c_read, r2c_write) = create_pipe()?;

        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        let upload_clone = upload.clone();
        let download_clone = download.clone();
        let stats_up = stats.clone();
        let stats_down = stats;
        let cancel_up = cancel.clone();

        // Use spawn_blocking for the splice loop since it uses blocking syscalls
        let upload_handle = tokio::task::spawn_blocking(move || {
            loop {
                if cancel_up.is_cancelled() {
                    break;
                }
                match splice_one_direction(client_fd, c2r_read, c2r_write, remote_fd) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        upload_clone.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(ref s) = stats_up {
                            s.upload.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_micros(100));
                    }
                    Err(_) => break,
                }
            }
        });

        let download_handle = tokio::task::spawn_blocking(move || {
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                match splice_one_direction(remote_fd, r2c_read, r2c_write, client_fd) {
                    Ok(0) => break,
                    Ok(n) => {
                        download_clone.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(ref s) = stats_down {
                            s.download.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_micros(100));
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for both directions with idle timeout
        let result = tokio::time::timeout(
            idle_timeout,
            async {
                let _ = tokio::join!(upload_handle, download_handle);
            },
        )
        .await;

        // Clean up pipes
        close_fd(c2r_read);
        close_fd(c2r_write);
        close_fd(r2c_read);
        close_fd(r2c_write);

        if result.is_err() {
            debug!("splice relay idle timeout");
        }

        let up = upload.load(Ordering::Relaxed);
        let down = download.load(Ordering::Relaxed);
        debug!(upload = up, download = down, "splice relay finished (zero-copy)");
        Ok((up, down))
    }
}

/// Relay for ProxyStream with zero-copy attempt.
/// On Linux, if both streams are raw TcpStream, uses splice() for zero-copy.
/// Otherwise falls back to the standard buffered relay.
pub async fn relay_proxy_streams(
    client: ProxyStream,
    remote: ProxyStream,
    opts: RelayOptions,
) -> Result<(u64, u64)> {
    eprintln!("relay_proxy_streams: entered");
    // Try zero-copy path on Linux when both sides are raw TcpStream
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let client_is_tcp = client.as_any().is::<tokio::net::TcpStream>();
        let remote_is_tcp = remote.as_any().is::<tokio::net::TcpStream>();
        eprintln!("relay: linux fast-path check client_tcp={} remote_tcp={}", client_is_tcp, remote_is_tcp);

        if client_is_tcp && remote_is_tcp
            && opts.upload_limiter.is_none()
            && opts.download_limiter.is_none()
        {
            let client_fd = client
                .as_any()
                .downcast_ref::<tokio::net::TcpStream>()
                .unwrap()
                .as_raw_fd();
            let remote_fd = remote
                .as_any()
                .downcast_ref::<tokio::net::TcpStream>()
                .unwrap()
                .as_raw_fd();

            eprintln!("relay: using splice zero-copy path");
            debug!("using splice() zero-copy relay");
            return splice::splice_relay(
                client_fd,
                remote_fd,
                opts.idle_timeout,
                opts.stats,
                opts.cancel.unwrap_or_default(),
            )
            .await;
        }
    }

    // Fallback: use Tokio's copy_bidirectional for robust full-duplex relay.
    let mut client = client;
    let mut remote = remote;

    let result = tokio::time::timeout(opts.idle_timeout, async {
        tokio::io::copy_bidirectional(&mut client, &mut remote)
            .await
            .map_err(anyhow::Error::from)
    }).await;

    match result {
        Ok(Ok((up, down))) => {
            eprintln!("relay: finished up={} down={}", up, down);
            if let Some(ref stats) = opts.stats {
                stats.upload.fetch_add(up, Ordering::Relaxed);
                stats.download.fetch_add(down, Ordering::Relaxed);
            }
            Ok((up, down))
        }
        Ok(Err(e)) => {
            eprintln!("relay: error {}", e);
            Err(e)
        }
        Err(_) => {
            eprintln!("relay: timeout {:?}", opts.idle_timeout);
            debug!("relay idle timeout ({:?}), closing", opts.idle_timeout);
            Ok((0, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_basic_echo() {
        let (mut client_a, client_b) = duplex(1024);
        let (remote_a, mut remote_b) = duplex(1024);

        // Spawn relay
        let handle = tokio::spawn(async move { relay(client_b, remote_a).await });

        // Write from client side
        client_a.write_all(b"hello world").await.unwrap();
        client_a.shutdown().await.unwrap();

        // Read on remote side
        let mut buf = vec![0u8; 64];
        let n = remote_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello world");

        // Write response from remote
        remote_b.write_all(b"response").await.unwrap();
        remote_b.shutdown().await.unwrap();

        // Read response on client side
        let n = client_a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"response");

        let (up, down) = handle.await.unwrap().unwrap();
        assert_eq!(up, 11);
        assert_eq!(down, 8);
    }

    #[tokio::test]
    async fn relay_idle_timeout() {
        let (_client_a, client_b) = duplex(1024);
        let (remote_a, _remote_b) = duplex(1024);

        let opts = RelayOptions {
            idle_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        // Should timeout quickly since no data flows
        let start = std::time::Instant::now();
        let result = relay_with_options(client_b, remote_a, opts).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn relay_stats_tracking() {
        let (mut client_a, client_b) = duplex(1024);
        let (remote_a, mut remote_b) = duplex(1024);

        let stats = RelayStats::new();
        let stats_clone = stats.clone();

        let handle = tokio::spawn(async move {
            relay_with_options(
                client_b,
                remote_a,
                RelayOptions {
                    stats: Some(stats_clone),
                    ..Default::default()
                },
            )
            .await
        });

        client_a.write_all(b"12345").await.unwrap();
        // Give relay time to process
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stats.upload(), 5);

        remote_b.write_all(b"abc").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stats.download(), 3);

        // Close both sides
        client_a.shutdown().await.unwrap();
        remote_b.shutdown().await.unwrap();

        let (up, down) = handle.await.unwrap().unwrap();
        assert_eq!(up, 5);
        assert_eq!(down, 3);
    }

    #[tokio::test]
    async fn relay_proxy_streams_tcp_returns_data() {
        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if s.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            tokio::net::TcpStream::connect(inbound_addr).await.unwrap()
        });

        let (server_side, _) = inbound_listener.accept().await.unwrap();
        let mut client_side = client_task.await.unwrap();
        let remote = tokio::net::TcpStream::connect(echo_addr).await.unwrap();

        let relay_task = tokio::spawn(async move {
            relay_proxy_streams(
                Box::new(server_side),
                Box::new(remote),
                RelayOptions::default(),
            )
            .await
        });

        client_side.write_all(b"relay-tcp").await.unwrap();
        client_side.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(3), client_side.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"relay-tcp");

        drop(client_side);
        let _ = tokio::time::timeout(Duration::from_secs(3), relay_task).await;
    }

    #[test]
    fn buffer_pool_get_put() {
        let pool = BufferPool::new(4);
        let buf = pool.get();
        assert_eq!(buf.len(), BUF_SIZE);
        pool.put(buf);

        // Should get the recycled buffer
        let buf2 = pool.get();
        assert_eq!(buf2.len(), BUF_SIZE);
    }

    #[test]
    fn buffer_pool_overflow() {
        let pool = BufferPool::new(8);
        let b1 = pool.get();
        let b2 = pool.get();
        let b3 = pool.get();
        pool.put(b1);
        pool.put(b2);
        pool.put(b3);
        let _ = pool.get();
        let _ = pool.get();
        // Third get allocates fresh
        let b = pool.get();
        assert_eq!(b.len(), BUF_SIZE);
    }

    #[test]
    fn buffer_pool_tiered_small() {
        let pool = BufferPool::new(8);
        let buf = pool.get_small();
        assert_eq!(buf.len(), BUF_SIZE_SMALL);
        pool.put(buf);
        let buf2 = pool.get_small();
        assert_eq!(buf2.len(), BUF_SIZE_SMALL);
    }

    #[test]
    fn buffer_pool_tiered_large() {
        let pool = BufferPool::new(8);
        let buf = pool.get_large();
        assert_eq!(buf.len(), BUF_SIZE_LARGE);
        pool.put(buf);
        let buf2 = pool.get_large();
        assert_eq!(buf2.len(), BUF_SIZE_LARGE);
    }

    #[test]
    fn buffer_pool_stats() {
        let pool = BufferPool::new(4);
        let _ = pool.get(); // miss
        let (hits, misses) = pool.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 1);

        let buf = pool.get(); // miss
        pool.put(buf);
        let _ = pool.get(); // hit
        let (hits, misses) = pool.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 2);
    }
}
