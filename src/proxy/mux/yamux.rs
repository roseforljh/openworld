use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::sync::Mutex;

/// yamux 多路复用协议实现
///
/// yamux (Yet another Multiplexer) 帧格式:
/// [version: 1B] [type: 1B] [flags: 2B] [stream_id: 4B] [length: 4B]
/// 总帧头 12 字节

const YAMUX_VERSION: u8 = 0;
const YAMUX_HEADER_SIZE: usize = 12;
const YAMUX_DEFAULT_WINDOW: u32 = 256 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum YamuxType {
    Data = 0x00,
    WindowUpdate = 0x01,
    Ping = 0x02,
    GoAway = 0x03,
}

impl YamuxType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::WindowUpdate),
            0x02 => Some(Self::Ping),
            0x03 => Some(Self::GoAway),
            _ => None,
        }
    }
}

pub mod yamux_flags {
    pub const SYN: u16 = 0x01;
    pub const ACK: u16 = 0x02;
    pub const FIN: u16 = 0x04;
    pub const RST: u16 = 0x08;
}

/// yamux 帧头
#[derive(Debug, Clone)]
pub struct YamuxHeader {
    pub version: u8,
    pub msg_type: YamuxType,
    pub flags: u16,
    pub stream_id: u32,
    pub length: u32,
}

impl YamuxHeader {
    pub fn encode(&self) -> [u8; YAMUX_HEADER_SIZE] {
        let mut buf = [0u8; YAMUX_HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.msg_type as u8;
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8; YAMUX_HEADER_SIZE]) -> Option<Self> {
        let msg_type = YamuxType::from_u8(buf[1])?;
        Some(Self {
            version: buf[0],
            msg_type,
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            stream_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            length: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

/// 构建 DATA 帧
pub fn encode_data(stream_id: u32, flags: u16, data: &[u8]) -> Vec<u8> {
    let header = YamuxHeader {
        version: YAMUX_VERSION,
        msg_type: YamuxType::Data,
        flags,
        stream_id,
        length: data.len() as u32,
    };
    let mut frame = Vec::with_capacity(YAMUX_HEADER_SIZE + data.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(data);
    frame
}

/// 构建 WINDOW_UPDATE 帧
pub fn encode_window_update(stream_id: u32, flags: u16, delta: u32) -> Vec<u8> {
    let header = YamuxHeader {
        version: YAMUX_VERSION,
        msg_type: YamuxType::WindowUpdate,
        flags,
        stream_id,
        length: delta,
    };
    header.encode().to_vec()
}

/// 构建 PING 帧
pub fn encode_ping(flags: u16, opaque: u32) -> Vec<u8> {
    let header = YamuxHeader {
        version: YAMUX_VERSION,
        msg_type: YamuxType::Ping,
        flags,
        stream_id: 0,
        length: opaque,
    };
    header.encode().to_vec()
}

/// 构建 GO_AWAY 帧
pub fn encode_goaway(reason: u32) -> Vec<u8> {
    let header = YamuxHeader {
        version: YAMUX_VERSION,
        msg_type: YamuxType::GoAway,
        flags: 0,
        stream_id: 0,
        length: reason,
    };
    header.encode().to_vec()
}

/// yamux 流状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    Init,
    SynSent,
    SynReceived,
    Established,
    LocalClose,
    RemoteClose,
    Closed,
    Reset,
}

/// yamux 单条逻辑流
pub struct YamuxStream {
    stream_id: u32,
    state: StreamState,
    recv_window: u32,
    send_window: u32,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl YamuxStream {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            state: StreamState::Init,
            recv_window: YAMUX_DEFAULT_WINDOW,
            send_window: YAMUX_DEFAULT_WINDOW,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn set_state(&mut self, state: StreamState) {
        self.state = state;
    }

    pub fn feed_data(&mut self, data: &[u8]) {
        self.read_buf.extend_from_slice(data);
    }

    pub fn readable_bytes(&self) -> usize {
        self.read_buf.len() - self.read_pos
    }

    pub fn read_data(&mut self, buf: &mut [u8]) -> usize {
        let available = &self.read_buf[self.read_pos..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos += n;
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
        }
        n
    }

    pub fn update_send_window(&mut self, delta: u32) {
        self.send_window = self.send_window.saturating_add(delta);
    }

    pub fn consume_send_window(&mut self, n: u32) -> bool {
        if self.send_window >= n {
            self.send_window -= n;
            true
        } else {
            false
        }
    }

    pub fn recv_window(&self) -> u32 {
        self.recv_window
    }

    pub fn send_window(&self) -> u32 {
        self.send_window
    }
}

/// yamux 会话（管理多条流）
pub struct YamuxSession {
    next_stream_id: AtomicU32,
    streams: Mutex<HashMap<u32, YamuxStream>>,
    is_client: bool,
    going_away: AtomicBool,
}

impl YamuxSession {
    pub fn client() -> Self {
        Self {
            next_stream_id: AtomicU32::new(1), // 客户端用奇数
            streams: Mutex::new(HashMap::new()),
            is_client: true,
            going_away: AtomicBool::new(false),
        }
    }

    pub fn server() -> Self {
        Self {
            next_stream_id: AtomicU32::new(2), // 服务端用偶数
            streams: Mutex::new(HashMap::new()),
            is_client: false,
            going_away: AtomicBool::new(false),
        }
    }

    pub fn is_client(&self) -> bool {
        self.is_client
    }

    pub fn is_going_away(&self) -> bool {
        self.going_away.load(Ordering::Relaxed)
    }

    pub fn set_going_away(&self) {
        self.going_away.store(true, Ordering::Relaxed);
    }

    /// 打开新流
    pub async fn open_stream(&self) -> u32 {
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let mut stream = YamuxStream::new(id);
        stream.set_state(StreamState::SynSent);
        self.streams.lock().await.insert(id, stream);
        id
    }

    /// 接受远端打开的流
    pub async fn accept_stream(&self, stream_id: u32) {
        let mut stream = YamuxStream::new(stream_id);
        stream.set_state(StreamState::Established);
        self.streams.lock().await.insert(stream_id, stream);
    }

    /// 获取活跃流数量
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// 关闭指定流
    pub async fn close_stream(&self, stream_id: u32) -> bool {
        let mut streams = self.streams.lock().await;
        if let Some(s) = streams.get_mut(&stream_id) {
            s.set_state(StreamState::Closed);
            streams.remove(&stream_id);
            true
        } else {
            false
        }
    }

    /// 向指定流推送数据
    pub async fn feed_stream(&self, stream_id: u32, data: &[u8]) -> bool {
        let mut streams = self.streams.lock().await;
        if let Some(s) = streams.get_mut(&stream_id) {
            s.feed_data(data);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yamux_header_roundtrip() {
        let header = YamuxHeader {
            version: YAMUX_VERSION,
            msg_type: YamuxType::Data,
            flags: yamux_flags::SYN,
            stream_id: 7,
            length: 1024,
        };
        let encoded = header.encode();
        let decoded = YamuxHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, YAMUX_VERSION);
        assert_eq!(decoded.msg_type, YamuxType::Data);
        assert_eq!(decoded.flags, yamux_flags::SYN);
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.length, 1024);
    }

    #[test]
    fn yamux_header_all_types() {
        for (t, expected) in [
            (YamuxType::Data, 0x00),
            (YamuxType::WindowUpdate, 0x01),
            (YamuxType::Ping, 0x02),
            (YamuxType::GoAway, 0x03),
        ] {
            assert_eq!(t as u8, expected);
            assert_eq!(YamuxType::from_u8(expected), Some(t));
        }
        assert_eq!(YamuxType::from_u8(0xFF), None);
    }

    #[test]
    fn yamux_header_all_flags() {
        let header = YamuxHeader {
            version: YAMUX_VERSION,
            msg_type: YamuxType::Data,
            flags: yamux_flags::SYN | yamux_flags::ACK | yamux_flags::FIN | yamux_flags::RST,
            stream_id: 1,
            length: 0,
        };
        let encoded = header.encode();
        let decoded = YamuxHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, 0x0F);
    }

    #[test]
    fn encode_data_frame() {
        let frame = encode_data(1, yamux_flags::SYN, b"hello");
        assert_eq!(frame.len(), YAMUX_HEADER_SIZE + 5);
        let header = YamuxHeader::decode(&frame[..YAMUX_HEADER_SIZE].try_into().unwrap()).unwrap();
        assert_eq!(header.msg_type, YamuxType::Data);
        assert_eq!(header.stream_id, 1);
        assert_eq!(header.length, 5);
        assert_eq!(&frame[YAMUX_HEADER_SIZE..], b"hello");
    }

    #[test]
    fn encode_window_update_frame() {
        let frame = encode_window_update(3, yamux_flags::ACK, 65536);
        assert_eq!(frame.len(), YAMUX_HEADER_SIZE);
        let header = YamuxHeader::decode(&frame[..].try_into().unwrap()).unwrap();
        assert_eq!(header.msg_type, YamuxType::WindowUpdate);
        assert_eq!(header.stream_id, 3);
        assert_eq!(header.length, 65536);
    }

    #[test]
    fn encode_ping_frame() {
        let frame = encode_ping(0, 42);
        assert_eq!(frame.len(), YAMUX_HEADER_SIZE);
        let header = YamuxHeader::decode(&frame[..].try_into().unwrap()).unwrap();
        assert_eq!(header.msg_type, YamuxType::Ping);
        assert_eq!(header.stream_id, 0);
        assert_eq!(header.length, 42);
    }

    #[test]
    fn encode_goaway_frame() {
        let frame = encode_goaway(0); // normal
        let header = YamuxHeader::decode(&frame[..].try_into().unwrap()).unwrap();
        assert_eq!(header.msg_type, YamuxType::GoAway);
        assert_eq!(header.length, 0);
    }

    #[test]
    fn yamux_stream_basic() {
        let mut stream = YamuxStream::new(1);
        assert_eq!(stream.stream_id(), 1);
        assert_eq!(stream.state(), StreamState::Init);
        assert_eq!(stream.recv_window(), YAMUX_DEFAULT_WINDOW);
        assert_eq!(stream.send_window(), YAMUX_DEFAULT_WINDOW);

        stream.set_state(StreamState::Established);
        assert_eq!(stream.state(), StreamState::Established);
    }

    #[test]
    fn yamux_stream_read_data() {
        let mut stream = YamuxStream::new(1);
        stream.feed_data(b"hello world");
        assert_eq!(stream.readable_bytes(), 11);

        let mut buf = [0u8; 5];
        let n = stream.read_data(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(stream.readable_bytes(), 6);

        let mut buf2 = [0u8; 10];
        let n2 = stream.read_data(&mut buf2);
        assert_eq!(n2, 6);
        assert_eq!(&buf2[..6], b" world");
        assert_eq!(stream.readable_bytes(), 0);
    }

    #[test]
    fn yamux_stream_window_management() {
        let mut stream = YamuxStream::new(1);
        assert!(stream.consume_send_window(100));
        assert_eq!(stream.send_window(), YAMUX_DEFAULT_WINDOW - 100);

        stream.update_send_window(50);
        assert_eq!(stream.send_window(), YAMUX_DEFAULT_WINDOW - 50);

        // Cannot consume more than available
        assert!(!stream.consume_send_window(u32::MAX));
    }

    #[tokio::test]
    async fn yamux_session_client() {
        let session = YamuxSession::client();
        assert!(session.is_client());
        assert!(!session.is_going_away());

        let id1 = session.open_stream().await;
        let id2 = session.open_stream().await;
        assert_eq!(id1 % 2, 1); // 奇数
        assert_eq!(id2 % 2, 1);
        assert_ne!(id1, id2);
        assert_eq!(session.stream_count().await, 2);
    }

    #[tokio::test]
    async fn yamux_session_server() {
        let session = YamuxSession::server();
        assert!(!session.is_client());

        session.accept_stream(1).await;
        assert_eq!(session.stream_count().await, 1);

        session.close_stream(1).await;
        assert_eq!(session.stream_count().await, 0);
    }

    #[tokio::test]
    async fn yamux_session_feed_stream() {
        let session = YamuxSession::client();
        let id = session.open_stream().await;

        assert!(session.feed_stream(id, b"test data").await);
        assert!(!session.feed_stream(9999, b"nope").await);
    }

    #[tokio::test]
    async fn yamux_session_goaway() {
        let session = YamuxSession::client();
        assert!(!session.is_going_away());
        session.set_going_away();
        assert!(session.is_going_away());
    }
}
