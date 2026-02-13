//! Userspace TCP/IP stack for TUN inbound.
//!
//! This module bridges the gap between raw IP packets from the TUN device
//! and the proxy's TCP stream abstraction. It uses smoltcp to:
//!
//! 1. Accept incoming TCP connections from the TUN device
//! 2. Reassemble TCP segments into ordered byte streams
//! 3. Present each connection as a standard AsyncRead + AsyncWrite stream
//! 4. Handle UDP packets as individual datagrams
//!
//! This is the equivalent of gVisor's netstack in sing-box or lwIP in mihomo.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::app::dispatcher::Dispatcher;
use crate::common::Address;
use crate::proxy::{InboundResult, Network, Session};

use super::tun_device::{IcmpPolicy, IpProtocol, ParsedPacket, TunDevice};

/// Maximum number of concurrent TCP connections through the TUN stack.
const MAX_TCP_CONNECTIONS: usize = 4096;
/// Maximum number of concurrent UDP sessions.
const MAX_UDP_SESSIONS: usize = 2048;
/// TCP connection buffer size (per direction).
const TCP_BUF_SIZE: usize = 256 * 1024; // 256 KiB
/// Channel buffer for packets from TUN device.
#[allow(dead_code)]
const TUN_CHANNEL_SIZE: usize = 4096;

/// A TCP connection extracted from the TUN stack.
/// Implements AsyncRead + AsyncWrite so it can be used as a ProxyStream.
pub struct TunTcpStream {
    /// Receive data from the stack (remote → local)
    rx: mpsc::Receiver<Vec<u8>>,
    /// Send data to the stack (local → remote)
    tx: mpsc::Sender<Vec<u8>>,
    /// Buffered read data
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Local (client) address
    local_addr: SocketAddr,
    /// Remote (destination) address
    remote_addr: SocketAddr,
    /// Whether the read side is closed
    read_closed: bool,
}

impl TunTcpStream {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            rx,
            tx,
            read_buf: Vec::new(),
            read_pos: 0,
            local_addr,
            remote_addr,
            read_closed: false,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl tokio::io::AsyncRead for TunTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain buffered data first
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }

        if self.read_closed {
            return std::task::Poll::Ready(Ok(())); // EOF
        }

        // Try to receive more data
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.read_closed = true;
                    return std::task::Poll::Ready(Ok(())); // EOF signal
                }
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf = data;
                    self.read_pos = to_copy;
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                self.read_closed = true;
                std::task::Poll::Ready(Ok(())) // Channel closed = EOF
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for TunTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let data = buf.to_vec();
        let len = data.len();
        match self.tx.try_send(data) {
            Ok(()) => std::task::Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Register waker and return pending
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "TUN stack channel closed"),
            )),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Send empty vec as EOF signal
        let _ = self.tx.try_send(Vec::new());
        std::task::Poll::Ready(Ok(()))
    }
}

/// TUN stack configuration.
#[derive(Debug, Clone)]
pub struct TunStackConfig {
    pub max_tcp_connections: usize,
    pub max_udp_sessions: usize,
    pub tcp_buf_size: usize,
    pub icmp_policy: IcmpPolicy,
    pub dns_hijack_enabled: bool,
    pub inbound_tag: String,
    pub sniff: bool,
    /// 是否允许 loopback 地址流量（127.0.0.0/8, ::1）
    /// false 时自动丢弃目标为 loopback 的包，避免路由循环
    pub allow_loopback: bool,
}

impl Default for TunStackConfig {
    fn default() -> Self {
        Self {
            max_tcp_connections: MAX_TCP_CONNECTIONS,
            max_udp_sessions: MAX_UDP_SESSIONS,
            tcp_buf_size: TCP_BUF_SIZE,
            icmp_policy: IcmpPolicy::Drop,
            dns_hijack_enabled: true,
            inbound_tag: "tun-in".to_string(),
            sniff: true,
            allow_loopback: false,
        }
    }
}

/// Connection key for tracking active TCP connections in the stack.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnKey {
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Debug, Clone)]
struct TcpConnState {
    client_seq_next: u32,
    server_seq_next: u32,
}

#[derive(Clone)]
struct TcpConnEntry {
    to_stream: mpsc::Sender<Vec<u8>>,
    state: Arc<tokio::sync::Mutex<TcpConnState>>,
}

/// The userspace TCP/IP stack that processes TUN packets.
pub struct TunStack {
    config: TunStackConfig,
    tcp_connections: tokio::sync::Mutex<HashMap<ConnKey, TcpConnEntry>>,
    /// Active connection count
    active_tcp: std::sync::atomic::AtomicUsize,
    active_udp: std::sync::atomic::AtomicUsize,
}

impl TunStack {
    pub fn new(config: TunStackConfig) -> Self {
        Self {
            config,
            tcp_connections: tokio::sync::Mutex::new(HashMap::new()),
            active_tcp: std::sync::atomic::AtomicUsize::new(0),
            active_udp: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn active_tcp_count(&self) -> usize {
        self.active_tcp.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn active_udp_count(&self) -> usize {
        self.active_udp.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Run the TUN stack: read packets from the device, dispatch connections.
    pub async fn run(
        self: Arc<Self>,
        device: Box<dyn TunDevice>,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
    ) -> Result<()> {
        info!(
            tag = self.config.inbound_tag,
            device = device.name(),
            "TUN stack started"
        );

        let device: Arc<dyn TunDevice> = Arc::from(device);
        let mut buf = vec![0u8; 65535]; // Max IP packet size

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("TUN stack shutting down");
                    break;
                }
                result = device.read_packet(&mut buf) => {
                    let n = match result {
                        Ok(n) if n == 0 => continue,
                        Ok(n) => n,
                        Err(e) => {
                            error!(error = %e, "TUN device read error");
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            continue;
                        }
                    };

                    let packet_data = &buf[..n];

                    // Parse the IP packet
                    let parsed = match super::tun_device::parse_ip_packet(packet_data) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!(error = %e, "failed to parse TUN packet");
                            continue;
                        }
                    };

                    // ICMP policy check
                    if parsed.protocol == IpProtocol::Icmp {
                        if !self.config.icmp_policy.should_process(&parsed) {
                            continue; // Drop
                        }
                    }

                    // Loopback 防护：丢弃目标为 loopback 地址的包
                    if !self.config.allow_loopback {
                        let is_loopback = match &parsed.dst_ip {
                            std::net::IpAddr::V4(v4) => v4.is_loopback(),
                            std::net::IpAddr::V6(v6) => v6.is_loopback(),
                        };
                        if is_loopback {
                            debug!(
                                src = %parsed.src_ip,
                                dst = %parsed.dst_ip,
                                "TUN loopback packet dropped (dst is loopback)"
                            );
                            continue;
                        }
                        // 同样检查源地址为 loopback 的包
                        let src_loopback = match &parsed.src_ip {
                            std::net::IpAddr::V4(v4) => v4.is_loopback(),
                            std::net::IpAddr::V6(v6) => v6.is_loopback(),
                        };
                        if src_loopback {
                            debug!(
                                src = %parsed.src_ip,
                                dst = %parsed.dst_ip,
                                "TUN loopback packet dropped (src is loopback)"
                            );
                            continue;
                        }
                    }

                    // DNS 劫持
                    if self.config.dns_hijack_enabled && super::dns_hijack::is_dns_query(&parsed) {
                        let resolver = dispatcher.resolver().await;
                        if let Some(response) = super::dns_hijack::handle_dns_hijack(
                            &parsed,
                            packet_data,
                            resolver.as_ref(),
                        ).await {
                            if let Err(e) = device.write_packet(&response).await {
                                debug!(error = %e, "TUN stack: DNS hijack write failed");
                            }
                        }
                        continue;
                    }

                    match parsed.protocol {
                        IpProtocol::Tcp => {
                            self.handle_tcp_packet(
                                &parsed,
                                packet_data,
                                &device,
                                &dispatcher,
                            )
                            .await;
                        }
                        IpProtocol::Udp => {
                            let this = Arc::clone(&self);
                            let parsed = parsed.clone();
                            let packet = packet_data.to_vec();
                            let device = device.clone();
                            let dispatcher = dispatcher.clone();
                            tokio::spawn(async move {
                                this.handle_udp_packet(parsed, packet, device, dispatcher).await;
                            });
                        }
                        IpProtocol::Icmp => {
                            debug!(
                                src = %parsed.src_ip,
                                dst = %parsed.dst_ip,
                                "ICMP packet passthrough (not yet implemented)"
                            );
                        }
                        IpProtocol::Other(proto) => {
                            debug!(protocol = proto, "unsupported IP protocol, dropping");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming TCP packet from the TUN device.
    async fn handle_tcp_packet(
        self: &Arc<Self>,
        parsed: &ParsedPacket,
        raw_packet: &[u8],
        device: &Arc<dyn TunDevice>,
        dispatcher: &Arc<Dispatcher>,
    ) {
        let src = SocketAddr::new(parsed.src_ip, parsed.src_port);
        let dst = SocketAddr::new(parsed.dst_ip, parsed.dst_port);
        let key = ConnKey { src, dst };

        // Extract TCP flags from the raw packet
        let tcp_offset = parsed.payload_offset;
        if raw_packet.len() < tcp_offset + 14 {
            return; // Too short for TCP header
        }
        let flags = raw_packet[tcp_offset + 13];
        let syn = flags & 0x02 != 0;
        let ack = flags & 0x10 != 0;
        let fin = flags & 0x01 != 0;
        let rst = flags & 0x04 != 0;

        let client_seq = u32::from_be_bytes([
            raw_packet[tcp_offset + 4],
            raw_packet[tcp_offset + 5],
            raw_packet[tcp_offset + 6],
            raw_packet[tcp_offset + 7],
        ]);

        // Extract TCP payload
        let data_offset = ((raw_packet[tcp_offset + 12] >> 4) as usize) * 4;
        let payload_start = tcp_offset + data_offset;
        let payload = if raw_packet.len() > payload_start {
            &raw_packet[payload_start..]
        } else {
            &[]
        };

        let existing = { self.tcp_connections.lock().await.get(&key).cloned() };
        if let Some(entry) = existing {
            if rst || fin {
                let _ = entry.to_stream.send(Vec::new()).await;
                self.tcp_connections.lock().await.remove(&key);
                self.active_tcp
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }

            let mut state = entry.state.lock().await;
            if ack && payload.is_empty() {
                return;
            }

            if !payload.is_empty() {
                let new_client_seq = client_seq.wrapping_add(payload.len() as u32);
                if new_client_seq > state.client_seq_next {
                    state.client_seq_next = new_client_seq;
                }

                let _ = entry.to_stream.send(payload.to_vec()).await;

                if let Ok(ack_pkt) = build_tcp_packet_ipv4(
                    dst,
                    src,
                    state.server_seq_next,
                    state.client_seq_next,
                    0x10,
                    &[],
                ) {
                    let _ = device.write_packet(&ack_pkt).await;
                }
            }
            return;
        }

        // New connection — only accept SYN
        if !syn {
            return;
        }

        // Check connection limit
        if self.active_tcp_count() >= self.config.max_tcp_connections {
            warn!(
                src = %src,
                dst = %dst,
                "TUN TCP connection limit reached, dropping SYN"
            );
            return;
        }

        // Create a new TunTcpStream pair
        let (stack_tx, stream_rx) = mpsc::channel::<Vec<u8>>(256);
        let (stream_tx, mut stack_rx) = mpsc::channel::<Vec<u8>>(256);

        let stream = TunTcpStream::new(stream_rx, stream_tx, src, dst);

        let state = Arc::new(tokio::sync::Mutex::new(TcpConnState {
            client_seq_next: client_seq.wrapping_add(1),
            server_seq_next: 1,
        }));

        {
            let st = state.lock().await;
            if let Ok(syn_ack) =
                build_tcp_packet_ipv4(dst, src, st.server_seq_next, st.client_seq_next, 0x12, &[])
            {
                let _ = device.write_packet(&syn_ack).await;
            }
        }

        {
            let mut st = state.lock().await;
            st.server_seq_next = st.server_seq_next.wrapping_add(1);
        }

        // Register the connection
        {
            let mut conns = self.tcp_connections.lock().await;
            conns.insert(
                key.clone(),
                TcpConnEntry {
                    to_stream: stack_tx,
                    state: state.clone(),
                },
            );
        }
        self.active_tcp
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Build session and dispatch
        let target = Address::Ip(dst);
        let session = Session {
            target,
            source: Some(src),
            inbound_tag: self.config.inbound_tag.clone(),
            network: Network::Tcp,
            sniff: self.config.sniff,
            detected_protocol: None,
        };

        let inbound_result = InboundResult {
            session,
            stream: Box::new(stream),
            udp_transport: None,
        };

        let dispatcher = dispatcher.clone();
        let this = Arc::clone(&self);
        let conn_key = key;
        let state_for_writer = state.clone();
        let device_for_writer = device.clone();

        tokio::spawn(async move {
            while let Some(data) = stack_rx.recv().await {
                if data.is_empty() {
                    break;
                }

                let mut st = state_for_writer.lock().await;
                if let Ok(pkt) = build_tcp_packet_ipv4(
                    dst,
                    src,
                    st.server_seq_next,
                    st.client_seq_next,
                    0x18,
                    &data,
                ) {
                    if device_for_writer.write_packet(&pkt).await.is_ok() {
                        st.server_seq_next = st.server_seq_next.wrapping_add(data.len() as u32);
                    }
                }
            }
        });

        tokio::spawn(async move {
            if let Err(e) = dispatcher.dispatch(inbound_result).await {
                debug!(error = %e, "TUN TCP dispatch error");
            }
            // Cleanup
            this.tcp_connections.lock().await.remove(&conn_key);
            this.active_tcp
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });

        debug!(
            src = %src,
            dst = %dst,
            "TUN: new TCP connection accepted"
        );
    }

    /// Handle an incoming UDP packet from the TUN device.
    async fn handle_udp_packet(
        self: &Arc<Self>,
        parsed: ParsedPacket,
        raw_packet: Vec<u8>,
        device: Arc<dyn TunDevice>,
        dispatcher: Arc<Dispatcher>,
    ) {
        let src = SocketAddr::new(parsed.src_ip, parsed.src_port);
        let dst = SocketAddr::new(parsed.dst_ip, parsed.dst_port);

        // Extract UDP payload
        let udp_offset = parsed.payload_offset;
        if raw_packet.len() < udp_offset + 8 {
            return; // Too short for UDP header
        }
        let payload = &raw_packet[udp_offset + 8..];

        if payload.is_empty() {
            return;
        }

        debug!(
            src = %src,
            dst = %dst,
            len = payload.len(),
            "TUN: UDP packet"
        );

        let target = Address::Ip(dst);
        let session = Session {
            target,
            source: Some(src),
            inbound_tag: self.config.inbound_tag.clone(),
            network: Network::Udp,
            sniff: false,
            detected_protocol: None,
        };

        let router = dispatcher.router().await;
        let (outbound_tag_ref, _) = router.route_with_rule(&session);
        let outbound_tag = outbound_tag_ref.to_string();
        drop(router);

        let outbound_manager = dispatcher.outbound_manager().await;
        let outbound = match outbound_manager.get(&outbound_tag) {
            Some(o) => o,
            None => {
                debug!(outbound = outbound_tag, "TUN UDP outbound not found");
                return;
            }
        };

        let packet = crate::common::UdpPacket {
            addr: Address::Ip(dst),
            data: bytes::Bytes::copy_from_slice(payload),
        };

        self.active_udp
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let result: Result<()> = async {
            let transport = outbound.connect_udp(&session).await?;
            transport.send(packet).await?;

            let reply = tokio::time::timeout(std::time::Duration::from_secs(5), transport.recv())
                .await
                .map_err(|_| anyhow::anyhow!("udp recv timeout"))??;

            let reply_src = match reply.addr {
                Address::Ip(addr) => addr,
                Address::Domain(_, _) => dst,
            };
            let packet_back = build_udp_reply_packet(reply_src, src, &reply.data)?;
            device.write_packet(&packet_back).await?;
            Ok(())
        }
        .await;

        if let Err(e) = result {
            debug!(error = %e, outbound = outbound.tag(), "TUN UDP forwarding failed");
        }

        self.active_udp
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn build_udp_reply_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (std::net::IpAddr::V4(src_ip), std::net::IpAddr::V4(dst_ip)) => {
            let ip_header_len = 20usize;
            let udp_header_len = 8usize;
            let total_len = ip_header_len + udp_header_len + payload.len();
            if total_len > u16::MAX as usize {
                anyhow::bail!("udp reply packet too large: {} bytes", total_len);
            }

            let mut packet = vec![0u8; total_len];
            packet[0] = 0x45;
            packet[1] = 0;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&0u16.to_be_bytes());
            packet[6..8].copy_from_slice(&0u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&src_ip.octets());
            packet[16..20].copy_from_slice(&dst_ip.octets());

            packet[20..22].copy_from_slice(&src.port().to_be_bytes());
            packet[22..24].copy_from_slice(&dst.port().to_be_bytes());
            packet[24..26]
                .copy_from_slice(&((udp_header_len + payload.len()) as u16).to_be_bytes());
            packet[26..28].copy_from_slice(&0u16.to_be_bytes());
            packet[28..].copy_from_slice(payload);

            let csum = ipv4_header_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&csum.to_be_bytes());
            Ok(packet)
        }
        _ => anyhow::bail!("ipv6 UDP reply injection is not implemented yet"),
    }
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        let word = u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_stack_config_defaults() {
        let config = TunStackConfig::default();
        assert_eq!(config.max_tcp_connections, MAX_TCP_CONNECTIONS);
        assert_eq!(config.max_udp_sessions, MAX_UDP_SESSIONS);
        assert_eq!(config.icmp_policy, IcmpPolicy::Drop);
        assert!(config.dns_hijack_enabled);
        assert!(config.sniff);
    }

    #[test]
    fn tun_stack_creation() {
        let stack = TunStack::new(TunStackConfig::default());
        assert_eq!(stack.active_tcp_count(), 0);
        assert_eq!(stack.active_udp_count(), 0);
    }

    #[tokio::test]
    async fn tun_tcp_stream_read_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (stack_tx, stream_rx) = mpsc::channel(16);
        let (stream_tx, mut stack_rx) = mpsc::channel(16);

        let mut stream = TunTcpStream::new(
            stream_rx,
            stream_tx,
            "127.0.0.1:1234".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        );

        // Write data through the stream
        stream.write_all(b"hello").await.unwrap();

        // Should appear on the stack side
        let data = stack_rx.recv().await.unwrap();
        assert_eq!(data, b"hello");

        // Push data from stack side
        stack_tx.send(b"world".to_vec()).await.unwrap();

        // Read from stream
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn tun_tcp_stream_eof() {
        use tokio::io::AsyncReadExt;

        let (stack_tx, stream_rx) = mpsc::channel(16);
        let (stream_tx, _stack_rx) = mpsc::channel(16);

        let mut stream = TunTcpStream::new(
            stream_rx,
            stream_tx,
            "127.0.0.1:1234".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        );

        // Send EOF signal
        stack_tx.send(Vec::new()).await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn tun_tcp_stream_channel_close() {
        use tokio::io::AsyncReadExt;

        let (stack_tx, stream_rx) = mpsc::channel(16);
        let (stream_tx, _stack_rx) = mpsc::channel(16);

        let mut stream = TunTcpStream::new(
            stream_rx,
            stream_tx,
            "127.0.0.1:1234".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        );

        // Drop the sender — channel closes
        drop(stack_tx);

        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[test]
    fn conn_key_equality() {
        let k1 = ConnKey {
            src: "127.0.0.1:1234".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let k2 = ConnKey {
            src: "127.0.0.1:1234".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        assert_eq!(k1, k2);

        let k3 = ConnKey {
            src: "127.0.0.1:1235".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn build_udp_reply_packet_ipv4_basic() {
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:53000".parse().unwrap();
        let payload = b"dns-reply";

        let packet = build_udp_reply_packet(src, dst, payload).unwrap();
        assert!(packet.len() >= 28 + payload.len());
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(packet[9], 17);
        assert_eq!(
            &packet[12..16],
            &src.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(
            &packet[16..20],
            &dst.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 53);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 53000);
        assert_eq!(&packet[28..], payload);
    }

    #[test]
    fn build_udp_reply_packet_ipv6_not_supported() {
        let src: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:53000".parse().unwrap();
        let err = build_udp_reply_packet(src, dst, b"x").unwrap_err();
        assert!(err.to_string().contains("ipv6"));
    }

    #[test]
    fn build_tcp_packet_ipv4_basic() {
        let src: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let payload = b"hello";

        let packet = build_tcp_packet_ipv4(src, dst, 100, 200, 0x18, payload).unwrap();
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(packet[9], 6);
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 443);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 50000);
        assert_eq!(
            u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]),
            100
        );
        assert_eq!(
            u32::from_be_bytes([packet[28], packet[29], packet[30], packet[31]]),
            200
        );
        assert_eq!(packet[33], 0x18);
        assert_eq!(&packet[40..], payload);
    }

    #[test]
    fn build_tcp_packet_ipv6_not_supported() {
        let src: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:50000".parse().unwrap();
        let err = build_tcp_packet_ipv4(src, dst, 1, 1, 0x10, b"").unwrap_err();
        assert!(err.to_string().contains("ipv6"));
    }
}

fn build_tcp_packet_ipv4(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => (s, d),
        _ => anyhow::bail!("ipv6 TCP packet injection is not implemented yet"),
    };

    let ip_header_len = 20usize;
    let tcp_header_len = 20usize;
    let total_len = ip_header_len + tcp_header_len + payload.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("tcp packet too large: {} bytes", total_len);
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    packet[20..22].copy_from_slice(&src.port().to_be_bytes());
    packet[22..24].copy_from_slice(&dst.port().to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&ack.to_be_bytes());
    packet[32] = (5u8 << 4) & 0xF0;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&(65535u16).to_be_bytes());
    packet[36..38].copy_from_slice(&0u16.to_be_bytes());
    packet[38..40].copy_from_slice(&0u16.to_be_bytes());
    packet[40..].copy_from_slice(payload);

    let ip_csum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let tcp_len = (tcp_header_len + payload.len()) as u16;
    let tcp_csum = tcp_checksum_ipv4(src_ip, dst_ip, &packet[20..], tcp_len);
    packet[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    Ok(packet)
}

fn tcp_checksum_ipv4(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    tcp_segment: &[u8],
    tcp_len: u16,
) -> u16 {
    let mut sum: u32 = 0;

    let src_octets = src.octets();
    let dst_octets = dst.octets();
    sum = sum.wrapping_add(u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32);
    sum = sum.wrapping_add(6u16 as u32);
    sum = sum.wrapping_add(tcp_len as u32);

    let mut i = 0usize;
    while i + 1 < tcp_segment.len() {
        let word = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < tcp_segment.len() {
        sum = sum.wrapping_add((tcp_segment[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
