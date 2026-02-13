use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

/// sing-mux frame types
const FRAME_NEW: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;
const FRAME_KEEPALIVE: u8 = 0x04;
const FRAME_PADDING: u8 = 0x05;
const FRAME_NEGOTIATE: u8 = 0x06;

/// Frame header: type(1) + stream_id(4) + length(2) = 7 bytes
const FRAME_HEADER_LEN: usize = 7;
const MAX_PAYLOAD_LEN: usize = 16384;

/// 默认 per-stream 接收窗口大小 (256KB)
const DEFAULT_RECEIVE_WINDOW: usize = 262144;

/// Mux 背压管理：per-stream 窗口级流控
#[derive(Debug)]
pub struct MuxBackpressure {
    window_size: usize,
    buffered: std::sync::atomic::AtomicUsize,
    paused: std::sync::atomic::AtomicBool,
}

impl MuxBackpressure {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            buffered: std::sync::atomic::AtomicUsize::new(0),
            paused: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_RECEIVE_WINDOW)
    }

    /// 记录接收到的数据量，返回是否应暂停读取
    pub fn on_data_received(&self, bytes: usize) -> bool {
        let prev = self
            .buffered
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        let total = prev + bytes;
        if total >= self.window_size {
            self.paused
                .store(true, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// 记录数据被消费，可能恢复读取
    pub fn on_data_consumed(&self, bytes: usize) -> bool {
        let prev = self.buffered.fetch_sub(
            bytes.min(self.buffered.load(std::sync::atomic::Ordering::Relaxed)),
            std::sync::atomic::Ordering::Relaxed,
        );
        let remaining = prev.saturating_sub(bytes);
        // 当缓冲量低于窗口的一半时恢复读取
        if remaining < self.window_size / 2
            && self.paused.load(std::sync::atomic::Ordering::Relaxed)
        {
            self.paused
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return true; // 恢复读取
        }
        false
    }

    /// 当前是否暂停读取
    pub fn is_paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 当前缓冲量
    pub fn buffered(&self) -> usize {
        self.buffered.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 窗口大小
    pub fn window_size(&self) -> usize {
        self.window_size
    }
}

#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub max_streams: u32,
    pub max_connections: u32,
    pub padding: bool,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_streams: 128,
            max_connections: 4,
            padding: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MuxFrame {
    pub frame_type: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl MuxFrame {
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        buf.push(self.frame_type);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < FRAME_HEADER_LEN {
            anyhow::bail!("insufficient data for mux frame header");
        }
        let frame_type = data[0];
        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let length = u16::from_be_bytes([data[5], data[6]]) as usize;
        let total = FRAME_HEADER_LEN + length;
        if data.len() < total {
            anyhow::bail!("insufficient data for mux frame payload");
        }
        let payload = data[FRAME_HEADER_LEN..total].to_vec();
        Ok((
            MuxFrame {
                frame_type,
                stream_id,
                payload,
            },
            total,
        ))
    }

    pub fn new_stream(stream_id: u32) -> Self {
        MuxFrame {
            frame_type: FRAME_NEW,
            stream_id,
            payload: Vec::new(),
        }
    }

    pub fn data(stream_id: u32, payload: Vec<u8>) -> Self {
        MuxFrame {
            frame_type: FRAME_DATA,
            stream_id,
            payload,
        }
    }

    pub fn close(stream_id: u32) -> Self {
        MuxFrame {
            frame_type: FRAME_CLOSE,
            stream_id,
            payload: Vec::new(),
        }
    }

    pub fn keepalive() -> Self {
        MuxFrame {
            frame_type: FRAME_KEEPALIVE,
            stream_id: 0,
            payload: Vec::new(),
        }
    }

    pub fn padding(size: usize) -> Self {
        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        MuxFrame {
            frame_type: FRAME_PADDING,
            stream_id: 0,
            payload,
        }
    }

    pub fn negotiate(features: &MuxNegotiation) -> Self {
        MuxFrame {
            frame_type: FRAME_NEGOTIATE,
            stream_id: 0,
            payload: features.encode(),
        }
    }

    pub fn is_padding(&self) -> bool {
        self.frame_type == FRAME_PADDING
    }

    pub fn is_negotiate(&self) -> bool {
        self.frame_type == FRAME_NEGOTIATE
    }
}

/// A multiplexed stream backed by channel I/O
pub struct MuxStream {
    stream_id: u32,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<MuxFrame>,
    read_buf: BytesMut,
    closed: bool,
}

impl MuxStream {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let to_copy = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        if self.closed {
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.put_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(MAX_PAYLOAD_LEN);
        let frame = MuxFrame::data(self.stream_id, buf[..len].to_vec());
        match self.write_tx.try_send(frame) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let frame = MuxFrame::close(self.stream_id);
        let _ = self.write_tx.try_send(frame);
        Poll::Ready(Ok(()))
    }
}

/// Client-side multiplexer: opens streams over a single connection
pub struct MuxClient {
    next_id: AtomicU32,
    config: MuxConfig,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    frame_tx: mpsc::Sender<MuxFrame>,
}

impl MuxClient {
    pub fn new(config: MuxConfig, frame_tx: mpsc::Sender<MuxFrame>) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            config,
            streams: Arc::new(Mutex::new(HashMap::new())),
            frame_tx,
        }
    }

    pub async fn open_stream(&self) -> Result<MuxStream> {
        let stream_id = self.next_id.fetch_add(2, Ordering::Relaxed); // odd IDs for client
        if stream_id / 2 >= self.config.max_streams {
            anyhow::bail!("max streams exceeded");
        }

        let (read_tx, read_rx) = mpsc::channel(64);
        self.streams.lock().await.insert(stream_id, read_tx);

        self.frame_tx
            .send(MuxFrame::new_stream(stream_id))
            .await
            .map_err(|_| anyhow::anyhow!("mux connection closed"))?;

        Ok(MuxStream {
            stream_id,
            read_rx,
            write_tx: self.frame_tx.clone(),
            read_buf: BytesMut::new(),
            closed: false,
        })
    }

    pub async fn dispatch_frame(&self, frame: MuxFrame) -> Result<()> {
        match frame.frame_type {
            FRAME_DATA => {
                let streams = self.streams.lock().await;
                if let Some(tx) = streams.get(&frame.stream_id) {
                    let _ = tx.send(frame.payload).await;
                }
            }
            FRAME_CLOSE => {
                let mut streams = self.streams.lock().await;
                if let Some(tx) = streams.remove(&frame.stream_id) {
                    let _ = tx.send(Vec::new()).await;
                }
            }
            FRAME_KEEPALIVE => {}
            _ => {}
        }
        Ok(())
    }

    pub fn streams(&self) -> &Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> {
        &self.streams
    }

    pub fn config(&self) -> &MuxConfig {
        &self.config
    }
}

/// Server-side multiplexer: accepts incoming streams
pub struct MuxServer {
    config: MuxConfig,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    frame_tx: mpsc::Sender<MuxFrame>,
    accept_tx: mpsc::Sender<MuxStream>,
    accept_rx: Mutex<mpsc::Receiver<MuxStream>>,
}

impl MuxServer {
    pub fn new(config: MuxConfig, frame_tx: mpsc::Sender<MuxFrame>) -> Self {
        let (accept_tx, accept_rx) = mpsc::channel(32);
        Self {
            config,
            streams: Arc::new(Mutex::new(HashMap::new())),
            frame_tx,
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
        }
    }

    pub async fn accept(&self) -> Option<MuxStream> {
        self.accept_rx.lock().await.recv().await
    }

    pub async fn dispatch_frame(&self, frame: MuxFrame) -> Result<()> {
        match frame.frame_type {
            FRAME_NEW => {
                if self.streams.lock().await.len() as u32 >= self.config.max_streams {
                    let close = MuxFrame::close(frame.stream_id);
                    let _ = self.frame_tx.send(close).await;
                    return Ok(());
                }
                let (read_tx, read_rx) = mpsc::channel(64);
                self.streams.lock().await.insert(frame.stream_id, read_tx);
                let stream = MuxStream {
                    stream_id: frame.stream_id,
                    read_rx,
                    write_tx: self.frame_tx.clone(),
                    read_buf: BytesMut::new(),
                    closed: false,
                };
                let _ = self.accept_tx.send(stream).await;
            }
            FRAME_DATA => {
                let streams = self.streams.lock().await;
                if let Some(tx) = streams.get(&frame.stream_id) {
                    let _ = tx.send(frame.payload).await;
                }
            }
            FRAME_CLOSE => {
                let mut streams = self.streams.lock().await;
                if let Some(tx) = streams.remove(&frame.stream_id) {
                    let _ = tx.send(Vec::new()).await;
                }
            }
            FRAME_KEEPALIVE => {}
            _ => {}
        }
        Ok(())
    }

    pub fn config(&self) -> &MuxConfig {
        &self.config
    }
}

/// Encode/decode mux frames from a byte buffer (for transport layer)
pub fn encode_frames(frames: &[MuxFrame]) -> Vec<u8> {
    let mut buf = Vec::new();
    for frame in frames {
        buf.extend_from_slice(&frame.encode());
    }
    buf
}

pub fn decode_frames(data: &[u8]) -> Result<(Vec<MuxFrame>, usize)> {
    let mut frames = Vec::new();
    let mut consumed = 0;
    while consumed + FRAME_HEADER_LEN <= data.len() {
        match MuxFrame::decode(&data[consumed..]) {
            Ok((frame, size)) => {
                consumed += size;
                frames.push(frame);
            }
            Err(_) => break,
        }
    }
    Ok((frames, consumed))
}

/// Mux 协商特性
#[derive(Debug, Clone)]
pub struct MuxNegotiation {
    pub padding_supported: bool,
    pub max_streams: u32,
    pub version: u8,
}

impl Default for MuxNegotiation {
    fn default() -> Self {
        Self {
            padding_supported: false,
            max_streams: 128,
            version: 1,
        }
    }
}

impl MuxNegotiation {
    pub fn with_padding(mut self) -> Self {
        self.padding_supported = true;
        self
    }

    pub fn with_max_streams(mut self, max: u32) -> Self {
        self.max_streams = max;
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6);
        buf.push(self.version);
        let flags: u8 = if self.padding_supported { 0x01 } else { 0x00 };
        buf.push(flags);
        buf.extend_from_slice(&self.max_streams.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            anyhow::bail!("mux negotiation too short");
        }
        let version = data[0];
        let padding_supported = (data[1] & 0x01) != 0;
        let max_streams = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        Ok(Self {
            padding_supported,
            max_streams,
            version,
        })
    }

    /// 合并两端的协商结果（取交集）
    pub fn merge(&self, other: &MuxNegotiation) -> MuxNegotiation {
        MuxNegotiation {
            padding_supported: self.padding_supported && other.padding_supported,
            max_streams: self.max_streams.min(other.max_streams),
            version: self.version.min(other.version),
        }
    }
}

/// Mux 填充策略
#[derive(Debug, Clone)]
pub struct MuxPaddingPolicy {
    pub enabled: bool,
    pub min_size: usize,
    pub max_size: usize,
    pub frequency: f64,
}

impl Default for MuxPaddingPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_size: 16,
            max_size: 256,
            frequency: 0.2,
        }
    }
}

impl MuxPaddingPolicy {
    pub fn should_pad(&self) -> bool {
        if !self.enabled {
            return false;
        }
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < self.frequency
    }

    pub fn generate_padding_frame(&self) -> Option<MuxFrame> {
        if !self.should_pad() {
            return None;
        }
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(self.min_size..=self.max_size);
        Some(MuxFrame::padding(size))
    }
}

/// Mux 协议自动协商器
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MuxProtocol {
    SingMux,
    Smux,
    Yamux,
    H2Mux,
}

impl MuxProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sing-mux" | "singmux" => Some(MuxProtocol::SingMux),
            "smux" => Some(MuxProtocol::Smux),
            "yamux" => Some(MuxProtocol::Yamux),
            "h2mux" | "h2" => Some(MuxProtocol::H2Mux),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MuxProtocol::SingMux => "sing-mux",
            MuxProtocol::Smux => "smux",
            MuxProtocol::Yamux => "yamux",
            MuxProtocol::H2Mux => "h2mux",
        }
    }
}

/// 自动选择 mux 协议（基于出站协议和配置）
pub fn auto_select_mux(outbound_protocol: &str, preferred: Option<&str>) -> MuxProtocol {
    if let Some(pref) = preferred {
        if let Some(proto) = MuxProtocol::from_str(pref) {
            return proto;
        }
    }
    match outbound_protocol {
        "vless" | "vmess" => MuxProtocol::SingMux,
        "trojan" => MuxProtocol::Smux,
        "ss" | "shadowsocks" => MuxProtocol::SingMux,
        _ => MuxProtocol::SingMux,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn frame_encode_decode_roundtrip() {
        let frame = MuxFrame::data(42, b"hello world".to_vec());
        let encoded = frame.encode();
        let (decoded, size) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(size, encoded.len());
        assert_eq!(decoded.frame_type, FRAME_DATA);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, b"hello world");
    }

    #[test]
    fn frame_new_stream() {
        let frame = MuxFrame::new_stream(7);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FRAME_NEW);
        assert_eq!(decoded.stream_id, 7);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn frame_close() {
        let frame = MuxFrame::close(99);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FRAME_CLOSE);
        assert_eq!(decoded.stream_id, 99);
    }

    #[test]
    fn frame_keepalive() {
        let frame = MuxFrame::keepalive();
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FRAME_KEEPALIVE);
        assert_eq!(decoded.stream_id, 0);
    }

    #[test]
    fn decode_multiple_frames() {
        let f1 = MuxFrame::data(1, b"aaa".to_vec());
        let f2 = MuxFrame::data(2, b"bbb".to_vec());
        let buf = encode_frames(&[f1, f2]);
        let (frames, consumed) = decode_frames(&buf).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(consumed, buf.len());
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[1].stream_id, 2);
    }

    #[test]
    fn decode_insufficient_header() {
        assert!(MuxFrame::decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn decode_insufficient_payload() {
        let frame = MuxFrame::data(1, b"hello".to_vec());
        let encoded = frame.encode();
        assert!(MuxFrame::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn mux_config_defaults() {
        let cfg = MuxConfig::default();
        assert_eq!(cfg.max_streams, 128);
        assert_eq!(cfg.max_connections, 4);
        assert!(!cfg.padding);
    }

    #[tokio::test]
    async fn mux_client_open_stream() {
        let (frame_tx, mut frame_rx) = mpsc::channel(64);
        let client = MuxClient::new(MuxConfig::default(), frame_tx);
        let stream = client.open_stream().await.unwrap();
        assert_eq!(stream.stream_id(), 1);
        let new_frame = frame_rx.recv().await.unwrap();
        assert_eq!(new_frame.frame_type, FRAME_NEW);
        assert_eq!(new_frame.stream_id, 1);
    }

    #[tokio::test]
    async fn mux_client_server_data_exchange() {
        let (client_tx, mut client_rx) = mpsc::channel::<MuxFrame>(64);
        let (server_tx, mut server_rx) = mpsc::channel::<MuxFrame>(64);

        let client = MuxClient::new(MuxConfig::default(), client_tx);
        let server = MuxServer::new(MuxConfig::default(), server_tx);

        let mut client_stream = client.open_stream().await.unwrap();
        let new_frame = client_rx.recv().await.unwrap();
        server.dispatch_frame(new_frame).await.unwrap();

        let mut server_stream = server.accept().await.unwrap();

        // Client writes data
        client_stream.write_all(b"hello from client").await.unwrap();
        let data_frame = client_rx.recv().await.unwrap();
        server.dispatch_frame(data_frame).await.unwrap();

        // Server reads data
        let mut buf = vec![0u8; 64];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from client");

        // Server writes back
        server_stream.write_all(b"hello from server").await.unwrap();
        let reply_frame = server_rx.recv().await.unwrap();
        client.dispatch_frame(reply_frame).await.unwrap();

        // Client reads reply
        let n = client_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from server");
    }

    #[tokio::test]
    async fn mux_stream_close() {
        let (client_tx, mut client_rx) = mpsc::channel::<MuxFrame>(64);
        let (server_tx, _) = mpsc::channel::<MuxFrame>(64);

        let client = MuxClient::new(MuxConfig::default(), client_tx);
        let server = MuxServer::new(MuxConfig::default(), server_tx);

        let client_stream = client.open_stream().await.unwrap();
        let new_frame = client_rx.recv().await.unwrap();
        server.dispatch_frame(new_frame).await.unwrap();

        let mut server_stream = server.accept().await.unwrap();

        // Client closes
        let close_frame = MuxFrame::close(client_stream.stream_id());
        server.dispatch_frame(close_frame).await.unwrap();

        // Server reads EOF
        let mut buf = vec![0u8; 64];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    // --- Padding tests ---

    #[test]
    fn padding_frame_has_correct_type() {
        let frame = MuxFrame::padding(32);
        assert_eq!(frame.frame_type, FRAME_PADDING);
        assert_eq!(frame.payload.len(), 32);
        assert!(frame.is_padding());
    }

    #[test]
    fn padding_frame_random_content() {
        let f1 = MuxFrame::padding(64);
        let f2 = MuxFrame::padding(64);
        // Extremely unlikely to be the same
        assert_ne!(f1.payload, f2.payload);
    }

    // --- Negotiation tests ---

    #[test]
    fn negotiate_encode_decode() {
        let neg = MuxNegotiation::default()
            .with_padding()
            .with_max_streams(64);
        let encoded = neg.encode();
        let decoded = MuxNegotiation::decode(&encoded).unwrap();
        assert!(decoded.padding_supported);
        assert_eq!(decoded.max_streams, 64);
        assert_eq!(decoded.version, 1);
    }

    #[test]
    fn negotiate_frame() {
        let neg = MuxNegotiation::default().with_padding();
        let frame = MuxFrame::negotiate(&neg);
        assert_eq!(frame.frame_type, FRAME_NEGOTIATE);
        assert!(frame.is_negotiate());
    }

    #[test]
    fn negotiate_merge_takes_intersection() {
        let a = MuxNegotiation {
            padding_supported: true,
            max_streams: 128,
            version: 1,
        };
        let b = MuxNegotiation {
            padding_supported: false,
            max_streams: 64,
            version: 1,
        };
        let merged = a.merge(&b);
        assert!(!merged.padding_supported); // false wins
        assert_eq!(merged.max_streams, 64); // min
    }

    #[test]
    fn negotiate_decode_too_short() {
        assert!(MuxNegotiation::decode(&[0u8; 3]).is_err());
    }

    // --- Padding policy tests ---

    #[test]
    fn padding_policy_disabled() {
        let policy = MuxPaddingPolicy::default();
        assert!(!policy.enabled);
        assert!(!policy.should_pad());
        assert!(policy.generate_padding_frame().is_none());
    }

    #[test]
    fn padding_policy_always() {
        let policy = MuxPaddingPolicy {
            enabled: true,
            min_size: 16,
            max_size: 32,
            frequency: 1.0, // always pad
        };
        assert!(policy.should_pad());
        let frame = policy.generate_padding_frame().unwrap();
        assert!(frame.payload.len() >= 16 && frame.payload.len() <= 32);
    }

    // --- Auto select tests ---

    #[test]
    fn auto_select_preferred() {
        assert_eq!(auto_select_mux("vless", Some("yamux")), MuxProtocol::Yamux);
        assert_eq!(auto_select_mux("vless", Some("smux")), MuxProtocol::Smux);
    }

    #[test]
    fn auto_select_by_protocol() {
        assert_eq!(auto_select_mux("vless", None), MuxProtocol::SingMux);
        assert_eq!(auto_select_mux("trojan", None), MuxProtocol::Smux);
    }

    #[test]
    fn mux_protocol_from_str() {
        assert_eq!(
            MuxProtocol::from_str("sing-mux"),
            Some(MuxProtocol::SingMux)
        );
        assert_eq!(MuxProtocol::from_str("smux"), Some(MuxProtocol::Smux));
        assert_eq!(MuxProtocol::from_str("yamux"), Some(MuxProtocol::Yamux));
        assert_eq!(MuxProtocol::from_str("h2mux"), Some(MuxProtocol::H2Mux));
        assert_eq!(MuxProtocol::from_str("unknown"), None);
    }

    #[test]
    fn mux_protocol_as_str() {
        assert_eq!(MuxProtocol::SingMux.as_str(), "sing-mux");
        assert_eq!(MuxProtocol::Smux.as_str(), "smux");
        assert_eq!(MuxProtocol::Yamux.as_str(), "yamux");
        assert_eq!(MuxProtocol::H2Mux.as_str(), "h2mux");
    }

    // --- Backpressure tests ---

    #[test]
    fn backpressure_default_window() {
        let bp = MuxBackpressure::with_default_window();
        assert_eq!(bp.window_size(), DEFAULT_RECEIVE_WINDOW);
        assert_eq!(bp.buffered(), 0);
        assert!(!bp.is_paused());
    }

    #[test]
    fn backpressure_pause_on_window_full() {
        let bp = MuxBackpressure::new(1000);
        bp.on_data_received(500);
        assert!(!bp.is_paused());
        let paused = bp.on_data_received(600); // total = 1100 > 1000
        assert!(paused);
        assert!(bp.is_paused());
    }

    #[test]
    fn backpressure_resume_after_consume() {
        let bp = MuxBackpressure::new(1000);
        bp.on_data_received(1100); // paused
        assert!(bp.is_paused());

        // Consume enough to go below half window (500)
        let resumed = bp.on_data_consumed(700); // remaining = 400 < 500
        assert!(resumed);
        assert!(!bp.is_paused());
    }

    #[test]
    fn backpressure_no_resume_if_still_above_half() {
        let bp = MuxBackpressure::new(1000);
        bp.on_data_received(1100);
        assert!(bp.is_paused());

        // Consume a little - still above half window
        let resumed = bp.on_data_consumed(100); // remaining = 1000 > 500
        assert!(!resumed);
        assert!(bp.is_paused());
    }

    #[test]
    fn backpressure_buffered_tracking() {
        let bp = MuxBackpressure::new(10000);
        bp.on_data_received(100);
        assert_eq!(bp.buffered(), 100);
        bp.on_data_received(200);
        assert_eq!(bp.buffered(), 300);
        bp.on_data_consumed(150);
        assert_eq!(bp.buffered(), 150);
    }

    #[test]
    fn backpressure_custom_window() {
        let bp = MuxBackpressure::new(4096);
        assert_eq!(bp.window_size(), 4096);

        // Fill window
        bp.on_data_received(4096);
        assert!(bp.is_paused());

        // Consume all
        bp.on_data_consumed(4096);
        assert!(!bp.is_paused());
        assert_eq!(bp.buffered(), 0);
    }
}
