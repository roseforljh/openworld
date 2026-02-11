use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::{TlsConfig, TransportConfig};

use super::StreamTransport;

/// WebSocket 传输
pub struct WsTransport {
    server_addr: String,
    server_port: u16,
    path: String,
    host: Option<String>,
    headers: Option<std::collections::HashMap<String, String>>,
    tls_config: Option<TlsConfig>,
}

impl WsTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        transport_config: &TransportConfig,
        tls_config: Option<TlsConfig>,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            path: transport_config
                .path
                .clone()
                .unwrap_or_else(|| "/".to_string()),
            host: transport_config.host.clone(),
            headers: transport_config.headers.clone(),
            tls_config,
        }
    }
}

#[async_trait]
impl StreamTransport for WsTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let use_tls = self.tls_config.as_ref().map_or(false, |c| c.enabled);
        let scheme = if use_tls { "wss" } else { "ws" };
        let host = self.host.as_deref().unwrap_or(&self.server_addr);

        // 建立底层 TCP 连接
        let tcp_addr = format!("{}:{}", self.server_addr, self.server_port);
        let tcp_stream = TcpStream::connect(&tcp_addr).await?;

        let stream: ProxyStream = if use_tls {
            let tls_cfg = self
                .tls_config
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TLS enabled but tls_config missing"))?;
            let sni = tls_cfg.sni.as_deref().unwrap_or(&self.server_addr);
            let alpn: Option<Vec<&str>> = tls_cfg
                .alpn
                .as_ref()
                .map(|v| v.iter().map(|s| s.as_str()).collect());
            let rustls_config =
                crate::common::tls::build_tls_config(tls_cfg.allow_insecure, alpn.as_deref())?;
            let connector =
                tokio_rustls::TlsConnector::from(std::sync::Arc::new(rustls_config));
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
            let tls_stream = connector.connect(server_name, tcp_stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };

        // 构建 WebSocket 请求
        let uri = format!("{}://{}:{}{}", scheme, host, self.server_port, self.path);
        let mut request = Request::builder()
            .uri(&uri)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );

        if let Some(ref headers) = self.headers {
            for (key, value) in headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let request = request.body(())?;

        // WebSocket 握手
        let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket handshake failed: {}", e))?;

        debug!(uri = uri, "WebSocket connection established");

        Ok(Box::new(WsStream::new(ws_stream)))
    }
}

/// 将 WebSocket 流适配为 AsyncRead + AsyncWrite
///
/// 内部维护 read buffer，将 WebSocket Binary 帧转为字节流语义。
pub struct WsStream {
    inner: WebSocketStream<ProxyStream>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl WsStream {
    fn new(inner: WebSocketStream<ProxyStream>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 如果 buffer 中还有数据，先消费
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 从 WebSocket 读取下一帧
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => match msg {
                Message::Binary(data) => {
                    let bytes: &[u8] = &data;
                    let to_copy = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..to_copy]);
                    if to_copy < bytes.len() {
                        self.read_buf = bytes[to_copy..].to_vec();
                        self.read_pos = 0;
                    }
                    Poll::Ready(Ok(()))
                }
                Message::Text(text) => {
                    let bytes: &[u8] = text.as_ref();
                    let to_copy = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..to_copy]);
                    if to_copy < bytes.len() {
                        self.read_buf = bytes[to_copy..].to_vec();
                        self.read_pos = 0;
                    }
                    Poll::Ready(Ok(()))
                }
                Message::Close(_) => Poll::Ready(Ok(())),
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                    // 忽略控制帧，继续读取
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let msg = Message::Binary(buf.to_vec().into());
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => match Pin::new(&mut self.inner).start_send(msg) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
