use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// H2 Mux: HTTP/2 风格的流级多路复用连接池
///
/// 在单个 TCP 连接上创建多个逻辑流，每个流有独立的 stream_id。
/// 帧格式: [length: 3B] [type: 1B] [flags: 1B] [stream_id: 4B] [payload]

const FRAME_HEADER_SIZE: usize = 9;
const DEFAULT_MAX_STREAMS: u32 = 100;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Data = 0x00,
    Headers = 0x01,
    RstStream = 0x03,
    Settings = 0x04,
    Ping = 0x06,
    GoAway = 0x07,
    WindowUpdate = 0x08,
}

impl FrameType {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::RstStream),
            0x04 => Some(Self::Settings),
            0x06 => Some(Self::Ping),
            0x07 => Some(Self::GoAway),
            0x08 => Some(Self::WindowUpdate),
            _ => None,
        }
    }
}

/// H2 帧标志位常量
pub mod frame_flags {
    pub const END_STREAM: u8 = 0x01;
    pub const END_HEADERS: u8 = 0x04;
    pub const PADDED: u8 = 0x08;
    pub const ACK: u8 = 0x01;
}

/// H2 帧头
#[derive(Debug, Clone)]
pub struct H2FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl H2FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_SIZE] {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        buf[0] = ((self.length >> 16) & 0xFF) as u8;
        buf[1] = ((self.length >> 8) & 0xFF) as u8;
        buf[2] = (self.length & 0xFF) as u8;
        buf[3] = self.frame_type as u8;
        buf[4] = self.flags;
        let id = self.stream_id & 0x7FFFFFFF;
        buf[5] = ((id >> 24) & 0xFF) as u8;
        buf[6] = ((id >> 16) & 0xFF) as u8;
        buf[7] = ((id >> 8) & 0xFF) as u8;
        buf[8] = (id & 0xFF) as u8;
        buf
    }

    pub fn decode(buf: &[u8; FRAME_HEADER_SIZE]) -> Self {
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let frame_type = FrameType::from_u8(buf[3]).unwrap_or(FrameType::Data);
        let flags = buf[4];
        let stream_id = ((buf[5] as u32) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);
        let stream_id = stream_id & 0x7FFFFFFF;
        Self {
            length,
            frame_type,
            flags,
            stream_id,
        }
    }
}

/// H2 连接池中的连接状态
struct PooledConnection {
    created_at: Instant,
    active_streams: Arc<AtomicU32>,
    max_streams: u32,
}

impl PooledConnection {
    fn available_capacity(&self) -> u32 {
        let active = self.active_streams.load(Ordering::Relaxed);
        if active >= self.max_streams {
            0
        } else {
            self.max_streams - active
        }
    }

    fn is_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() > max_age
    }
}

/// H2 Mux 连接池
pub struct H2MuxPool {
    max_streams_per_conn: u32,
    max_idle_time: Duration,
    next_stream_id: AtomicU64,
    connections: Mutex<VecDeque<PooledConnection>>,
}

impl H2MuxPool {
    pub fn new(max_streams_per_conn: u32, max_idle_secs: u64) -> Self {
        Self {
            max_streams_per_conn: max_streams_per_conn.max(1),
            max_idle_time: Duration::from_secs(max_idle_secs),
            next_stream_id: AtomicU64::new(1),
            connections: Mutex::new(VecDeque::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_STREAMS, 300)
    }

    fn next_stream_id(&self) -> u32 {
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        ((id & 0x7FFFFFFF) | 1) as u32 // 确保奇数 (client-initiated)
    }

    pub async fn pool_size(&self) -> usize {
        self.connections.lock().await.len()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut conns = self.connections.lock().await;
        let before = conns.len();
        conns.retain(|c| !c.is_expired(self.max_idle_time) && c.available_capacity() > 0);
        before - conns.len()
    }

    pub async fn add_connection(&self) -> u32 {
        let conn = PooledConnection {
            created_at: Instant::now(),
            active_streams: Arc::new(AtomicU32::new(0)),
            max_streams: self.max_streams_per_conn,
        };
        let mut conns = self.connections.lock().await;
        conns.push_back(conn);
        let stream_id = self.next_stream_id();
        stream_id
    }

    pub async fn try_acquire_stream(&self) -> Option<(usize, u32)> {
        let conns = self.connections.lock().await;
        for (idx, conn) in conns.iter().enumerate() {
            if !conn.is_expired(self.max_idle_time) && conn.available_capacity() > 0 {
                conn.active_streams.fetch_add(1, Ordering::Relaxed);
                let stream_id = self.next_stream_id();
                return Some((idx, stream_id));
            }
        }
        None
    }
}

/// H2 Mux Stream: 单个逻辑流
pub struct H2MuxStream {
    stream_id: u32,
    read_buf: Vec<u8>,
    read_pos: usize,
    closed: bool,
}

impl H2MuxStream {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            read_buf: Vec::new(),
            read_pos: 0,
            closed: false,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn feed_data(&mut self, data: &[u8]) {
        self.read_buf.extend_from_slice(data);
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn readable_bytes(&self) -> usize {
        self.read_buf.len() - self.read_pos
    }
}

/// 构造 DATA 帧
pub fn encode_data_frame(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
    let header = H2FrameHeader {
        length: data.len() as u32,
        frame_type: FrameType::Data,
        flags: if end_stream { 0x01 } else { 0x00 },
        stream_id,
    };
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(data);
    frame
}

/// 构造 RST_STREAM 帧
pub fn encode_rst_stream(stream_id: u32, error_code: u32) -> Vec<u8> {
    let header = H2FrameHeader {
        length: 4,
        frame_type: FrameType::RstStream,
        flags: 0,
        stream_id,
    };
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 4);
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&error_code.to_be_bytes());
    frame
}

/// 构造 PING 帧
pub fn encode_ping(ack: bool, opaque_data: [u8; 8]) -> Vec<u8> {
    let header = H2FrameHeader {
        length: 8,
        frame_type: FrameType::Ping,
        flags: if ack { 0x01 } else { 0x00 },
        stream_id: 0,
    };
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 8);
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&opaque_data);
    frame
}

/// 构造 GOAWAY 帧
pub fn encode_goaway(last_stream_id: u32, error_code: u32) -> Vec<u8> {
    let header = H2FrameHeader {
        length: 8,
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
    };
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 8);
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&last_stream_id.to_be_bytes());
    frame.extend_from_slice(&error_code.to_be_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrip() {
        let header = H2FrameHeader {
            length: 1234,
            frame_type: FrameType::Data,
            flags: 0x01,
            stream_id: 5,
        };
        let encoded = header.encode();
        let decoded = H2FrameHeader::decode(&encoded);
        assert_eq!(decoded.length, 1234);
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.flags, 0x01);
        assert_eq!(decoded.stream_id, 5);
    }

    #[test]
    fn frame_header_max_length() {
        let header = H2FrameHeader {
            length: 0xFFFFFF,
            frame_type: FrameType::Headers,
            flags: 0x04,
            stream_id: 0x7FFFFFFF,
        };
        let encoded = header.encode();
        let decoded = H2FrameHeader::decode(&encoded);
        assert_eq!(decoded.length, 0xFFFFFF);
        assert_eq!(decoded.stream_id, 0x7FFFFFFF);
    }

    #[test]
    fn frame_header_stream_id_mask() {
        let header = H2FrameHeader {
            length: 0,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: 0x80000001, // reserved bit set
        };
        let encoded = header.encode();
        let decoded = H2FrameHeader::decode(&encoded);
        assert_eq!(decoded.stream_id, 1); // reserved bit cleared
    }

    #[test]
    fn encode_data_frame_basic() {
        let frame = encode_data_frame(1, b"hello", false);
        assert_eq!(frame.len(), FRAME_HEADER_SIZE + 5);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.length, 5);
        assert_eq!(header.frame_type, FrameType::Data);
        assert_eq!(header.flags, 0x00);
        assert_eq!(header.stream_id, 1);
        assert_eq!(&frame[FRAME_HEADER_SIZE..], b"hello");
    }

    #[test]
    fn encode_data_frame_end_stream() {
        let frame = encode_data_frame(3, b"fin", true);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.flags, 0x01); // END_STREAM
    }

    #[test]
    fn encode_rst_stream_basic() {
        let frame = encode_rst_stream(5, 0x02);
        assert_eq!(frame.len(), FRAME_HEADER_SIZE + 4);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.frame_type, FrameType::RstStream);
        assert_eq!(header.stream_id, 5);
        let error_code = u32::from_be_bytes(frame[FRAME_HEADER_SIZE..].try_into().unwrap());
        assert_eq!(error_code, 0x02);
    }

    #[test]
    fn encode_ping_basic() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = encode_ping(false, data);
        assert_eq!(frame.len(), FRAME_HEADER_SIZE + 8);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.frame_type, FrameType::Ping);
        assert_eq!(header.flags, 0x00);
        assert_eq!(header.stream_id, 0);
    }

    #[test]
    fn encode_ping_ack() {
        let data = [0u8; 8];
        let frame = encode_ping(true, data);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.flags, 0x01); // ACK
    }

    #[test]
    fn encode_goaway_basic() {
        let frame = encode_goaway(7, 0x00);
        assert_eq!(frame.len(), FRAME_HEADER_SIZE + 8);
        let header = H2FrameHeader::decode(&frame[..FRAME_HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.frame_type, FrameType::GoAway);
        assert_eq!(header.stream_id, 0);
        let last_id = u32::from_be_bytes(frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 4].try_into().unwrap());
        let error = u32::from_be_bytes(frame[FRAME_HEADER_SIZE + 4..].try_into().unwrap());
        assert_eq!(last_id, 7);
        assert_eq!(error, 0);
    }

    #[test]
    fn h2mux_stream_basic() {
        let mut stream = H2MuxStream::new(1);
        assert_eq!(stream.stream_id(), 1);
        assert!(!stream.is_closed());
        assert_eq!(stream.readable_bytes(), 0);

        stream.feed_data(b"hello");
        assert_eq!(stream.readable_bytes(), 5);

        stream.close();
        assert!(stream.is_closed());
    }

    #[tokio::test]
    async fn h2mux_pool_basic() {
        let pool = H2MuxPool::with_defaults();
        assert_eq!(pool.pool_size().await, 0);

        pool.add_connection().await;
        assert_eq!(pool.pool_size().await, 1);

        let result = pool.try_acquire_stream().await;
        assert!(result.is_some());
        let (idx, stream_id) = result.unwrap();
        assert_eq!(idx, 0);
        assert!(stream_id > 0);
    }

    #[tokio::test]
    async fn h2mux_pool_cleanup() {
        let pool = H2MuxPool::new(100, 0); // 0 second idle time = expire immediately
        pool.add_connection().await;
        assert_eq!(pool.pool_size().await, 1);

        tokio::time::sleep(Duration::from_millis(10)).await;
        let cleaned = pool.cleanup_expired().await;
        assert_eq!(cleaned, 1);
        assert_eq!(pool.pool_size().await, 0);
    }

    #[test]
    fn frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0x00), Some(FrameType::Data));
        assert_eq!(FrameType::from_u8(0x01), Some(FrameType::Headers));
        assert_eq!(FrameType::from_u8(0x03), Some(FrameType::RstStream));
        assert_eq!(FrameType::from_u8(0x04), Some(FrameType::Settings));
        assert_eq!(FrameType::from_u8(0x06), Some(FrameType::Ping));
        assert_eq!(FrameType::from_u8(0x07), Some(FrameType::GoAway));
        assert_eq!(FrameType::from_u8(0x08), Some(FrameType::WindowUpdate));
        assert_eq!(FrameType::from_u8(0xFF), None);
    }
}
