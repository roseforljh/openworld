use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// smux protocol version
const SMUX_VERSION: u8 = 1;

/// smux frame commands
const CMD_SYN: u8 = 0;   // stream open
const CMD_FIN: u8 = 1;   // stream close
const CMD_PSH: u8 = 2;   // data push
const CMD_NOP: u8 = 3;   // nop / keepalive

/// smux frame header: version(1) + cmd(1) + length(2) + stream_id(4) = 8 bytes
const SMUX_HEADER_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct SmuxFrame {
    pub version: u8,
    pub cmd: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl SmuxFrame {
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(SMUX_HEADER_LEN + self.payload.len());
        buf.push(self.version);
        buf.push(self.cmd);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < SMUX_HEADER_LEN {
            anyhow::bail!("insufficient data for smux frame header");
        }
        let version = data[0];
        let cmd = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let total = SMUX_HEADER_LEN + length;
        if data.len() < total {
            anyhow::bail!("insufficient data for smux frame payload");
        }
        let payload = data[SMUX_HEADER_LEN..total].to_vec();
        Ok((
            SmuxFrame {
                version,
                cmd,
                stream_id,
                payload,
            },
            total,
        ))
    }

    pub fn syn(stream_id: u32) -> Self {
        SmuxFrame { version: SMUX_VERSION, cmd: CMD_SYN, stream_id, payload: Vec::new() }
    }

    pub fn fin(stream_id: u32) -> Self {
        SmuxFrame { version: SMUX_VERSION, cmd: CMD_FIN, stream_id, payload: Vec::new() }
    }

    pub fn psh(stream_id: u32, data: Vec<u8>) -> Self {
        SmuxFrame { version: SMUX_VERSION, cmd: CMD_PSH, stream_id, payload: data }
    }

    pub fn nop() -> Self {
        SmuxFrame { version: SMUX_VERSION, cmd: CMD_NOP, stream_id: 0, payload: Vec::new() }
    }
}

/// smux stream backed by channel I/O
pub struct SmuxStream {
    stream_id: u32,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<SmuxFrame>,
    read_buf: BytesMut,
    closed: bool,
}

impl SmuxStream {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl AsyncRead for SmuxStream {
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

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(65535);
        let frame = SmuxFrame::psh(self.stream_id, buf[..len].to_vec());
        match self.write_tx.try_send(frame) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "smux closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.write_tx.try_send(SmuxFrame::fin(self.stream_id));
        Poll::Ready(Ok(()))
    }
}

/// smux session (client-side): opens streams over a single connection
pub struct SmuxSession {
    next_id: AtomicU32,
    frame_tx: mpsc::Sender<SmuxFrame>,
    streams: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
}

impl SmuxSession {
    pub fn new(frame_tx: mpsc::Sender<SmuxFrame>) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            frame_tx,
            streams: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub async fn open_stream(&self) -> Result<SmuxStream> {
        let stream_id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let (read_tx, read_rx) = mpsc::channel(64);
        self.streams.lock().await.insert(stream_id, read_tx);
        self.frame_tx.send(SmuxFrame::syn(stream_id)).await
            .map_err(|_| anyhow::anyhow!("smux session closed"))?;
        Ok(SmuxStream {
            stream_id,
            read_rx,
            write_tx: self.frame_tx.clone(),
            read_buf: BytesMut::new(),
            closed: false,
        })
    }

    pub async fn dispatch_frame(&self, frame: SmuxFrame) -> Result<()> {
        match frame.cmd {
            CMD_PSH => {
                let streams = self.streams.lock().await;
                if let Some(tx) = streams.get(&frame.stream_id) {
                    let _ = tx.send(frame.payload).await;
                }
            }
            CMD_FIN => {
                let mut streams = self.streams.lock().await;
                if let Some(tx) = streams.remove(&frame.stream_id) {
                    let _ = tx.send(Vec::new()).await;
                }
            }
            CMD_NOP => {}
            _ => {}
        }
        Ok(())
    }
}

/// Decode multiple smux frames from a byte buffer
pub fn decode_smux_frames(data: &[u8]) -> Result<(Vec<SmuxFrame>, usize)> {
    let mut frames = Vec::new();
    let mut consumed = 0;
    while consumed + SMUX_HEADER_LEN <= data.len() {
        match SmuxFrame::decode(&data[consumed..]) {
            Ok((frame, size)) => {
                consumed += size;
                frames.push(frame);
            }
            Err(_) => break,
        }
    }
    Ok((frames, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn smux_frame_encode_decode_roundtrip() {
        let frame = SmuxFrame::psh(42, b"hello smux".to_vec());
        let encoded = frame.encode();
        let (decoded, size) = SmuxFrame::decode(&encoded).unwrap();
        assert_eq!(size, encoded.len());
        assert_eq!(decoded.version, SMUX_VERSION);
        assert_eq!(decoded.cmd, CMD_PSH);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, b"hello smux");
    }

    #[test]
    fn smux_frame_syn() {
        let frame = SmuxFrame::syn(7);
        let encoded = frame.encode();
        let (decoded, _) = SmuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.cmd, CMD_SYN);
        assert_eq!(decoded.stream_id, 7);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn smux_frame_fin() {
        let frame = SmuxFrame::fin(99);
        let encoded = frame.encode();
        let (decoded, _) = SmuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.cmd, CMD_FIN);
        assert_eq!(decoded.stream_id, 99);
    }

    #[test]
    fn smux_frame_nop() {
        let frame = SmuxFrame::nop();
        let encoded = frame.encode();
        let (decoded, _) = SmuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.cmd, CMD_NOP);
        assert_eq!(decoded.stream_id, 0);
    }

    #[test]
    fn smux_decode_multiple() {
        let f1 = SmuxFrame::psh(1, b"aaa".to_vec());
        let f2 = SmuxFrame::psh(2, b"bbb".to_vec());
        let mut buf = Vec::new();
        buf.extend_from_slice(&f1.encode());
        buf.extend_from_slice(&f2.encode());
        let (frames, consumed) = decode_smux_frames(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[1].stream_id, 2);
    }

    #[test]
    fn smux_decode_insufficient_header() {
        assert!(SmuxFrame::decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn smux_decode_insufficient_payload() {
        let frame = SmuxFrame::psh(1, b"hello".to_vec());
        let encoded = frame.encode();
        assert!(SmuxFrame::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[tokio::test]
    async fn smux_session_open_and_data() {
        let (frame_tx, mut frame_rx) = mpsc::channel::<SmuxFrame>(64);
        let session = SmuxSession::new(frame_tx);

        let mut stream = session.open_stream().await.unwrap();
        assert_eq!(stream.stream_id(), 1);

        // SYN frame sent
        let syn = frame_rx.recv().await.unwrap();
        assert_eq!(syn.cmd, CMD_SYN);
        assert_eq!(syn.stream_id, 1);

        // Write data
        stream.write_all(b"test data").await.unwrap();
        let psh = frame_rx.recv().await.unwrap();
        assert_eq!(psh.cmd, CMD_PSH);
        assert_eq!(psh.payload, b"test data");

        // Dispatch incoming data
        let reply = SmuxFrame::psh(1, b"reply".to_vec());
        session.dispatch_frame(reply).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[tokio::test]
    async fn smux_session_close_stream() {
        let (frame_tx, mut frame_rx) = mpsc::channel::<SmuxFrame>(64);
        let session = SmuxSession::new(frame_tx);

        let mut stream = session.open_stream().await.unwrap();
        let _ = frame_rx.recv().await; // SYN

        // Remote closes
        session.dispatch_frame(SmuxFrame::fin(1)).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }
}
