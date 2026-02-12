use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::TlsConfig;

use super::{ech, fingerprint, StreamTransport};

/// HTTP/2 传输
///
/// 通过 HTTP/2 POST 请求建立双向数据隧道。
/// 每次 connect() 创建独立的 H2 连接和流。
pub struct H2Transport {
    server_addr: String,
    server_port: u16,
    path: String,
    host: String,
    tls_config: Option<TlsConfig>,
    dialer_config: Option<DialerConfig>,
}

impl H2Transport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        path: Option<String>,
        host: Option<String>,
        tls_config: Option<TlsConfig>,
        dialer_config: Option<DialerConfig>,
    ) -> Self {
        let host = host.unwrap_or_else(|| server_addr.clone());
        let path = path.unwrap_or_else(|| "/".to_string());
        Self {
            server_addr,
            server_port,
            path,
            host,
            tls_config,
            dialer_config,
        }
    }
}

#[async_trait]
impl StreamTransport for H2Transport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let tcp = super::dial_tcp(&self.server_addr, self.server_port, &self.dialer_config).await?;

        let stream: ProxyStream = if let Some(ref tls_cfg) = self.tls_config {
            let sni = tls_cfg.sni.as_deref().unwrap_or(&self.server_addr);
            let alpn: Vec<&str> = vec!["h2"];
            let fp = tls_cfg
                .fingerprint
                .as_deref()
                .map(fingerprint::FingerprintType::from_str)
                .unwrap_or(fingerprint::FingerprintType::None);
            let ech_settings = ech::resolve_ech_settings(tls_cfg, sni).await?;
            let rustls_config =
                ech::build_ech_tls_config(&ech_settings, fp, tls_cfg.allow_insecure, Some(&alpn))?;
            let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
            let tls = connector.connect(server_name, tcp).await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        let (send_request, connection) = h2::client::handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("H2 handshake failed: {}", e))?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(error = %e, "H2 connection terminated");
            }
        });

        let request = http::Request::builder()
            .method("POST")
            .uri(&self.path)
            .header("host", &self.host)
            .body(())
            .map_err(|e| anyhow::anyhow!("failed to build H2 request: {}", e))?;

        let (response_future, send_stream) = send_request
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("H2 not ready: {}", e))?
            .send_request(request, false)
            .map_err(|e| anyhow::anyhow!("H2 send_request failed: {}", e))?;

        let response = response_future
            .await
            .map_err(|e| anyhow::anyhow!("H2 response failed: {}", e))?;
        let recv_stream = response.into_body();

        debug!(path = %self.path, host = %self.host, "H2 stream established");

        Ok(Box::new(H2Stream::new(send_stream, recv_stream)))
    }
}

/// 将 h2 SendStream + RecvStream 适配为 AsyncRead + AsyncWrite
pub(crate) struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl H2Stream {
    pub(crate) fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先消费缓冲区
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 从 H2 接收新数据
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let _ = self.recv.flow_control().release_capacity(data.len());
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data[n..].to_vec();
                    self.read_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.send.reserve_capacity(buf.len());

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let n = buf.len().min(capacity);
                let data = Bytes::copy_from_slice(&buf[..n]);
                self.send.send_data(data, false).map_err(io::Error::other)?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "h2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}
