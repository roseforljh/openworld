use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::TlsConfig;

use super::{ech, fingerprint, StreamTransport};

const DEFAULT_SERVICE_NAME: &str = "GunService";

/// gRPC 传输（gun 模式）
///
/// 在 HTTP/2 之上使用 gRPC 帧封装数据。
/// 每个数据块包裹在 5 字节 gRPC 头中：[compressed:1][length:4 BE]
pub struct GrpcTransport {
    server_addr: String,
    server_port: u16,
    service_name: String,
    host: String,
    tls_config: Option<TlsConfig>,
}

impl GrpcTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        service_name: Option<String>,
        host: Option<String>,
        tls_config: Option<TlsConfig>,
    ) -> Self {
        let host = host.unwrap_or_else(|| server_addr.clone());
        let service_name = service_name.unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
        Self {
            server_addr,
            server_port,
            service_name,
            host,
            tls_config,
        }
    }
}

#[async_trait]
impl StreamTransport for GrpcTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let tcp_addr = format!("{}:{}", self.server_addr, self.server_port);
        let tcp = TcpStream::connect(&tcp_addr).await?;

        let stream: ProxyStream = if let Some(ref tls_cfg) = self.tls_config {
            let sni = tls_cfg.sni.as_deref().unwrap_or(&self.server_addr);
            let alpn: Vec<&str> = vec!["h2"];
            let fp = tls_cfg
                .fingerprint
                .as_deref()
                .map(fingerprint::FingerprintType::from_str)
                .unwrap_or(fingerprint::FingerprintType::None);
            let ech_settings = ech::EchSettings {
                config_list: tls_cfg
                    .ech_config
                    .as_deref()
                    .map(ech::parse_ech_config_base64)
                    .transpose()?,
                grease: tls_cfg.ech_grease,
                outer_sni: tls_cfg.ech_outer_sni.clone(),
            };
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
            .map_err(|e| anyhow::anyhow!("gRPC H2 handshake failed: {}", e))?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(error = %e, "gRPC H2 connection terminated");
            }
        });

        let path = format!("/{}/Tun", self.service_name);
        let request = http::Request::builder()
            .method("POST")
            .uri(&path)
            .header("host", &self.host)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(|e| anyhow::anyhow!("failed to build gRPC request: {}", e))?;

        let (response_future, send_stream) = send_request
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("gRPC H2 not ready: {}", e))?
            .send_request(request, false)
            .map_err(|e| anyhow::anyhow!("gRPC send_request failed: {}", e))?;

        let response = response_future
            .await
            .map_err(|e| anyhow::anyhow!("gRPC response failed: {}", e))?;
        let recv_stream = response.into_body();

        debug!(service = %self.service_name, "gRPC stream established");

        Ok(Box::new(GrpcStream::new(send_stream, recv_stream)))
    }
}

/// 带 gRPC 帧封装的 H2 流适配器
///
/// 写入时自动添加 5 字节 gRPC 头，读取时自动剥离。
struct GrpcStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// 从 H2 接收到的原始字节（待 gRPC 解帧）
    recv_buf: BytesMut,
    /// 已解帧的有效载荷
    out_buf: Vec<u8>,
    out_pos: usize,
}

impl GrpcStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: BytesMut::new(),
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }

    /// 尝试从 recv_buf 解析一个完整的 gRPC 帧
    fn try_decode_frame(&mut self) -> bool {
        if self.recv_buf.len() < 5 {
            return false;
        }
        let payload_len = u32::from_be_bytes([
            self.recv_buf[1],
            self.recv_buf[2],
            self.recv_buf[3],
            self.recv_buf[4],
        ]) as usize;

        if self.recv_buf.len() < 5 + payload_len {
            return false;
        }

        self.recv_buf.advance(5);
        let payload = self.recv_buf.split_to(payload_len);
        self.out_buf.extend_from_slice(&payload);
        true
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先返回已解帧的数据
        if self.out_pos < self.out_buf.len() {
            let remaining = &self.out_buf[self.out_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.out_pos += n;
            if self.out_pos >= self.out_buf.len() {
                self.out_buf.clear();
                self.out_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 循环：接收 H2 数据 → 尝试解帧
        loop {
            if self.try_decode_frame() {
                let n = self.out_buf.len().min(buf.remaining());
                buf.put_slice(&self.out_buf[..n]);
                self.out_pos = n;
                if self.out_pos >= self.out_buf.len() {
                    self.out_buf.clear();
                    self.out_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    self.recv_buf.extend_from_slice(&data);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // gRPC 帧 = [0x00][u32 BE length][payload]
        let frame_len = 5 + buf.len();
        self.send.reserve_capacity(frame_len);

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                if capacity < 6 {
                    // 容量不足以发送 header + 至少 1 字节
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let max_payload = (capacity - 5).min(buf.len());
                let mut frame = BytesMut::with_capacity(5 + max_payload);
                frame.extend_from_slice(&[0x00]);
                frame.extend_from_slice(&(max_payload as u32).to_be_bytes());
                frame.extend_from_slice(&buf[..max_payload]);

                self.send
                    .send_data(frame.freeze(), false)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(max_payload))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "grpc stream closed",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_frame_encode() {
        let payload = b"hello";
        let mut frame = BytesMut::with_capacity(5 + payload.len());
        frame.extend_from_slice(&[0x00]);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        assert_eq!(frame.len(), 10);
        assert_eq!(frame[0], 0x00); // not compressed
        assert_eq!(
            u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
            5
        );
        assert_eq!(&frame[5..], b"hello");
    }

    #[test]
    fn grpc_frame_decode() {
        let payload = b"world";
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00]);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);

        // 模拟解帧
        assert!(buf.len() >= 5);
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(len, 5);
        assert!(buf.len() >= 5 + len);
        buf.advance(5);
        let decoded = buf.split_to(len);
        assert_eq!(&decoded[..], b"world");
    }

    #[test]
    fn grpc_frame_decode_partial() {
        // 不完整的帧
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x0A]); // length = 10
        buf.extend_from_slice(b"hel"); // only 3 bytes, need 10

        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(len, 10);
        assert!(buf.len() < 5 + len); // incomplete
    }

    #[test]
    fn grpc_frame_decode_multiple() {
        let mut buf = BytesMut::new();
        // 帧 1: "abc"
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x03]);
        buf.extend_from_slice(b"abc");
        // 帧 2: "de"
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02]);
        buf.extend_from_slice(b"de");

        // 解帧 1
        let len1 = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        buf.advance(5);
        let payload1 = buf.split_to(len1);
        assert_eq!(&payload1[..], b"abc");

        // 解帧 2
        let len2 = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        buf.advance(5);
        let payload2 = buf.split_to(len2);
        assert_eq!(&payload2[..], b"de");
    }
}
