pub mod h2mux;
pub mod singmux;
pub mod smux;
pub mod xudp;
pub mod yamux;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use crate::common::ProxyStream;
use crate::config::types::MuxConfig;

pub use h2mux::{
    encode_data_frame, encode_rst_stream, frame_flags as h2_frame_flags, FrameType, H2FrameHeader,
    H2MuxPool, H2MuxStream,
};
pub use singmux::{
    auto_select_mux, decode_frames, encode_frames, MuxBackpressure, MuxClient,
    MuxConfig as SingMuxConfig, MuxFrame, MuxNegotiation, MuxPaddingPolicy, MuxProtocol, MuxServer,
};
pub use smux::{decode_smux_frames, SmuxFrame, SmuxSession, SmuxStream};
pub use xudp::{XudpFrame, XudpMux};
pub use yamux::{
    encode_data as encode_yamux_data, yamux_flags, YamuxHeader, YamuxSession, YamuxStream,
    YamuxType,
};

type StreamFuture = Pin<Box<dyn Future<Output = Result<ProxyStream>> + Send>>;
pub type StreamConnector = Arc<dyn Fn() -> StreamFuture + Send + Sync>;

#[async_trait]
pub trait MuxTransport: Send + Sync {
    async fn open_stream(&self) -> Result<ProxyStream>;
}

pub struct MuxManager {
    config: MuxConfig,
    connector: StreamConnector,
    connections: Mutex<Vec<Arc<MuxConnection>>>,
}

impl MuxManager {
    pub fn new(config: MuxConfig, connector: StreamConnector) -> Self {
        Self {
            config,
            connector,
            connections: Mutex::new(Vec::new()),
        }
    }

    async fn pick_connection(&self) -> Option<Arc<MuxConnection>> {
        let conns = self.connections.lock().await;
        conns.iter().find(|c| c.has_capacity()).cloned()
    }

    async fn create_connection(&self) -> Result<Arc<MuxConnection>> {
        let base_stream = (self.connector)().await?;
        let runtime = build_runtime(&self.config, base_stream).await?;
        let conn = Arc::new(MuxConnection::new(
            runtime,
            self.config.max_streams_per_connection.max(1),
        ));
        self.connections.lock().await.push(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl MuxTransport for MuxManager {
    async fn open_stream(&self) -> Result<ProxyStream> {
        if let Some(conn) = self.pick_connection().await {
            return conn.open_stream().await;
        }

        let can_create = {
            let conns = self.connections.lock().await;
            conns.len() < self.config.max_connections.max(1)
        };

        if !can_create {
            anyhow::bail!("mux connection pool exhausted")
        }

        let conn = self.create_connection().await?;
        conn.open_stream().await
    }
}

struct MuxConnection {
    runtime: RuntimeConnection,
    active_streams: Arc<AtomicUsize>,
    max_streams: usize,
}

impl MuxConnection {
    fn new(runtime: RuntimeConnection, max_streams: usize) -> Self {
        Self {
            runtime,
            active_streams: Arc::new(AtomicUsize::new(0)),
            max_streams,
        }
    }

    fn has_capacity(&self) -> bool {
        self.active_streams.load(Ordering::Relaxed) < self.max_streams
    }

    async fn open_stream(&self) -> Result<ProxyStream> {
        if self.active_streams.load(Ordering::Relaxed) >= self.max_streams {
            anyhow::bail!("mux stream capacity reached")
        }
        self.active_streams.fetch_add(1, Ordering::Relaxed);

        let stream = match &self.runtime {
            RuntimeConnection::Sing(client) => Box::new(client.open_stream().await?) as ProxyStream,
            RuntimeConnection::Smux(session) => {
                Box::new(session.open_stream().await?) as ProxyStream
            }
            RuntimeConnection::Yamux(runtime) => {
                Box::new(runtime.open_stream().await?) as ProxyStream
            }
            RuntimeConnection::H2(runtime) => Box::new(runtime.open_stream().await?) as ProxyStream,
        };

        Ok(Box::new(ManagedMuxStream::new(
            stream,
            self.active_streams.clone(),
        )))
    }
}

enum RuntimeConnection {
    Sing(Arc<MuxClient>),
    Smux(Arc<SmuxSession>),
    Yamux(Arc<YamuxRuntime>),
    H2(Arc<H2Runtime>),
}

async fn build_runtime(config: &MuxConfig, stream: ProxyStream) -> Result<RuntimeConnection> {
    let proto = config.protocol.to_lowercase();
    match proto.as_str() {
        "sing-mux" | "singmux" => build_sing_runtime(config, stream).await,
        "smux" => build_smux_runtime(stream).await,
        "yamux" => build_yamux_runtime(stream).await,
        "h2mux" | "h2" => build_h2_runtime(stream).await,
        other => anyhow::bail!("unsupported mux protocol: {}", other),
    }
}

async fn build_sing_runtime(config: &MuxConfig, stream: ProxyStream) -> Result<RuntimeConnection> {
    let (frame_tx, mut frame_rx) = mpsc::channel::<MuxFrame>(256);
    let client = Arc::new(MuxClient::new(
        SingMuxConfig {
            max_streams: config.max_streams_per_connection as u32,
            max_connections: config.max_connections as u32,
            padding: config.padding,
        },
        frame_tx,
    ));

    let (mut reader, mut writer) = tokio::io::split(stream);
    let reader_client = client.clone();

    tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if writer.write_all(&frame.encode()).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut io_buf = [0u8; 8192];
        let mut decode_buf = BytesMut::new();
        loop {
            let n = match reader.read(&mut io_buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            decode_buf.extend_from_slice(&io_buf[..n]);
            let Ok((frames, consumed)) = decode_frames(&decode_buf) else {
                continue;
            };
            if consumed > 0 {
                decode_buf.advance(consumed);
            }
            for frame in frames {
                let _ = reader_client.dispatch_frame(frame).await;
            }
        }
    });

    Ok(RuntimeConnection::Sing(client))
}

async fn build_smux_runtime(stream: ProxyStream) -> Result<RuntimeConnection> {
    let (frame_tx, mut frame_rx) = mpsc::channel::<SmuxFrame>(256);
    let session = Arc::new(SmuxSession::new(frame_tx));

    let (mut reader, mut writer) = tokio::io::split(stream);
    let reader_session = session.clone();

    tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if writer.write_all(&frame.encode()).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut io_buf = [0u8; 8192];
        let mut decode_buf = BytesMut::new();
        loop {
            let n = match reader.read(&mut io_buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            decode_buf.extend_from_slice(&io_buf[..n]);
            let Ok((frames, consumed)) = decode_smux_frames(&decode_buf) else {
                continue;
            };
            if consumed > 0 {
                decode_buf.advance(consumed);
            }
            for frame in frames {
                let _ = reader_session.dispatch_frame(frame).await;
            }
        }
    });

    Ok(RuntimeConnection::Smux(session))
}

struct YamuxRuntime {
    session: Arc<YamuxSession>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    write_tx: mpsc::Sender<YamuxWriteCmd>,
}

enum YamuxWriteCmd {
    Open(u32),
    Data(u32, Vec<u8>),
    Close(u32),
}

impl YamuxRuntime {
    async fn open_stream(&self) -> Result<YamuxIoStream> {
        let stream_id = self.session.open_stream().await;
        let (read_tx, read_rx) = mpsc::channel(64);
        self.streams.lock().await.insert(stream_id, read_tx);
        self.write_tx
            .send(YamuxWriteCmd::Open(stream_id))
            .await
            .map_err(|_| anyhow::anyhow!("yamux session closed"))?;

        Ok(YamuxIoStream {
            stream_id,
            read_rx,
            write_tx: self.write_tx.clone(),
            read_buf: BytesMut::new(),
            closed: false,
        })
    }
}

async fn build_yamux_runtime(stream: ProxyStream) -> Result<RuntimeConnection> {
    let session = Arc::new(YamuxSession::client());
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (write_tx, mut write_rx) = mpsc::channel::<YamuxWriteCmd>(256);

    let (mut reader, mut writer) = tokio::io::split(stream);
    let streams_reader = streams.clone();

    tokio::spawn(async move {
        while let Some(cmd) = write_rx.recv().await {
            let bytes = match cmd {
                YamuxWriteCmd::Open(stream_id) => {
                    encode_yamux_data(stream_id, yamux_flags::SYN, &[])
                }
                YamuxWriteCmd::Data(stream_id, data) => encode_yamux_data(stream_id, 0, &data),
                YamuxWriteCmd::Close(stream_id) => {
                    encode_yamux_data(stream_id, yamux_flags::FIN, &[])
                }
            };
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    tokio::spawn(async move {
        loop {
            let mut header_buf = [0u8; 12];
            if reader.read_exact(&mut header_buf).await.is_err() {
                break;
            }
            let Some(header) = YamuxHeader::decode(&header_buf) else {
                break;
            };

            let mut payload = vec![0u8; header.length as usize];
            if !payload.is_empty() && reader.read_exact(&mut payload).await.is_err() {
                break;
            }

            if header.msg_type == YamuxType::Data {
                if !payload.is_empty() {
                    let tx = {
                        let streams = streams_reader.lock().await;
                        streams.get(&header.stream_id).cloned()
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(payload).await;
                    }
                }

                if header.flags & (yamux_flags::FIN | yamux_flags::RST) != 0 {
                    let tx = {
                        let mut streams = streams_reader.lock().await;
                        streams.remove(&header.stream_id)
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(Vec::new()).await;
                    }
                }
            }
        }
    });

    Ok(RuntimeConnection::Yamux(Arc::new(YamuxRuntime {
        session,
        streams,
        write_tx,
    })))
}

struct H2Runtime {
    pool: Arc<H2MuxPool>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    write_tx: mpsc::Sender<H2WriteCmd>,
}

enum H2WriteCmd {
    Open(u32),
    Data(u32, Vec<u8>),
    Close(u32),
}

impl H2Runtime {
    async fn open_stream(&self) -> Result<H2IoStream> {
        let stream_id = if let Some((_, id)) = self.pool.try_acquire_stream().await {
            id
        } else {
            self.pool.add_connection().await
        };

        let (read_tx, read_rx) = mpsc::channel(64);
        self.streams.lock().await.insert(stream_id, read_tx);
        self.write_tx
            .send(H2WriteCmd::Open(stream_id))
            .await
            .map_err(|_| anyhow::anyhow!("h2mux session closed"))?;

        Ok(H2IoStream {
            stream_id,
            read_rx,
            write_tx: self.write_tx.clone(),
            read_buf: BytesMut::new(),
            closed: false,
        })
    }
}

async fn build_h2_runtime(stream: ProxyStream) -> Result<RuntimeConnection> {
    let pool = Arc::new(H2MuxPool::with_defaults());
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (write_tx, mut write_rx) = mpsc::channel::<H2WriteCmd>(256);

    let (mut reader, mut writer) = tokio::io::split(stream);
    let streams_reader = streams.clone();

    tokio::spawn(async move {
        while let Some(cmd) = write_rx.recv().await {
            let bytes = match cmd {
                H2WriteCmd::Open(stream_id) => {
                    let header = H2FrameHeader {
                        length: 0,
                        frame_type: FrameType::Headers,
                        flags: h2_frame_flags::END_HEADERS,
                        stream_id,
                    };
                    header.encode().to_vec()
                }
                H2WriteCmd::Data(stream_id, data) => encode_data_frame(stream_id, &data, false),
                H2WriteCmd::Close(stream_id) => encode_rst_stream(stream_id, 0),
            };
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    tokio::spawn(async move {
        loop {
            let mut header_buf = [0u8; 9];
            if reader.read_exact(&mut header_buf).await.is_err() {
                break;
            }
            let header = H2FrameHeader::decode(&header_buf);

            let mut payload = vec![0u8; header.length as usize];
            if !payload.is_empty() && reader.read_exact(&mut payload).await.is_err() {
                break;
            }

            match header.frame_type {
                FrameType::Data => {
                    if !payload.is_empty() {
                        let tx = {
                            let streams = streams_reader.lock().await;
                            streams.get(&header.stream_id).cloned()
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(payload).await;
                        }
                    }

                    if header.flags & h2_frame_flags::END_STREAM != 0 {
                        let tx = {
                            let mut streams = streams_reader.lock().await;
                            streams.remove(&header.stream_id)
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(Vec::new()).await;
                        }
                    }
                }
                FrameType::RstStream => {
                    let tx = {
                        let mut streams = streams_reader.lock().await;
                        streams.remove(&header.stream_id)
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(Vec::new()).await;
                    }
                }
                _ => {}
            }
        }
    });

    Ok(RuntimeConnection::H2(Arc::new(H2Runtime {
        pool,
        streams,
        write_tx,
    })))
}

struct ManagedMuxStream {
    inner: ProxyStream,
    active_streams: Arc<AtomicUsize>,
}

impl ManagedMuxStream {
    fn new(inner: ProxyStream, active_streams: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            active_streams,
        }
    }
}

impl Drop for ManagedMuxStream {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for ManagedMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ManagedMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct YamuxIoStream {
    stream_id: u32,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<YamuxWriteCmd>,
    read_buf: BytesMut,
    closed: bool,
}

impl AsyncRead for YamuxIoStream {
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

impl AsyncWrite for YamuxIoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(16384);
        match self
            .write_tx
            .try_send(YamuxWriteCmd::Data(self.stream_id, buf[..len].to_vec()))
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "yamux session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.write_tx.try_send(YamuxWriteCmd::Close(self.stream_id));
        Poll::Ready(Ok(()))
    }
}

struct H2IoStream {
    stream_id: u32,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<H2WriteCmd>,
    read_buf: BytesMut,
    closed: bool,
}

impl AsyncRead for H2IoStream {
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

impl AsyncWrite for H2IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(16384);
        match self
            .write_tx
            .try_send(H2WriteCmd::Data(self.stream_id, buf[..len].to_vec()))
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2mux session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.write_tx.try_send(H2WriteCmd::Close(self.stream_id));
        Poll::Ready(Ok(()))
    }
}
