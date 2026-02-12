//! TLS 分片传输层。
//!
//! 将 TLS ClientHello 拆分成多个小 TCP 段发送，绕过基于明文匹配的 DPI 防火墙。
//!
//! 参考: sing-box 1.12 TLS fragment / record fragment

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::config::types::TlsFragmentConfig;

/// TCP 流包装器，在 TLS 握手阶段将数据拆分为随机大小的小段。
///
/// 握手完成后自动"退化"为直通模式（不再分片），避免影响数据传输性能。
pub struct FragmentStream<S> {
    inner: S,
    config: TlsFragmentConfig,
    /// 握手缓冲区: 累积一次完整写入，然后分片发送
    pending_fragments: Vec<Vec<u8>>,
    /// 当前正在发送的分片索引
    current_fragment_idx: usize,
    /// 当前分片已发送的字节偏移
    current_offset: usize,
    /// 是否已完成握手（TLS 握手在前几次写入完成）
    handshake_writes: u32,
    /// 握手后退化为直通（TLS 握手一般 2-3 次写入）
    max_handshake_writes: u32,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S, config: TlsFragmentConfig) -> Self {
        Self {
            inner,
            config,
            pending_fragments: Vec::new(),
            current_fragment_idx: 0,
            current_offset: 0,
            handshake_writes: 0,
            max_handshake_writes: 5,
        }
    }

    /// 将数据按随机大小拆分为多个分片
    fn split_to_fragments(data: &[u8], min_len: usize, max_len: usize) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let mut fragments = Vec::new();
        let mut offset = 0;

        let min_len = min_len.max(1);
        let max_len = max_len.max(min_len);

        while offset < data.len() {
            let chunk_size = rng.gen_range(min_len..=max_len).min(data.len() - offset);
            fragments.push(data[offset..offset + chunk_size].to_vec());
            offset += chunk_size;
        }

        fragments
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 握手阶段后直通
        if self.handshake_writes >= self.max_handshake_writes {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        // 还有未发完的分片 — 继续发送
        if !self.pending_fragments.is_empty() {
            return self.poll_send_pending(cx, buf.len());
        }

        // 新的写入 — 生成分片
        self.handshake_writes += 1;

        let fragments = Self::split_to_fragments(
            buf,
            self.config.min_length,
            self.config.max_length,
        );

        let total_len = buf.len();
        debug!(
            fragments = fragments.len(),
            total_bytes = total_len,
            write_num = self.handshake_writes,
            "TLS fragment: splitting write"
        );

        self.pending_fragments = fragments;
        self.current_fragment_idx = 0;
        self.current_offset = 0;

        self.poll_send_pending(cx, total_len)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncWrite + Unpin> FragmentStream<S> {
    /// 逐个发送缓冲的分片
    fn poll_send_pending(
        &mut self,
        cx: &mut Context<'_>,
        original_len: usize,
    ) -> Poll<io::Result<usize>> {
        while self.current_fragment_idx < self.pending_fragments.len() {
            let frag = &self.pending_fragments[self.current_fragment_idx];
            let remaining = &frag[self.current_offset..];

            if remaining.is_empty() {
                self.current_fragment_idx += 1;
                self.current_offset = 0;
                continue;
            }

            match Pin::new(&mut self.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    self.current_offset += n;
                    // 如果当前分片发完了，前进到下一个
                    if self.current_offset >= frag.len() {
                        self.current_fragment_idx += 1;
                        self.current_offset = 0;
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.pending_fragments.clear();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // 所有分片发送完毕
        self.pending_fragments.clear();
        self.current_fragment_idx = 0;
        self.current_offset = 0;

        Poll::Ready(Ok(original_len))
    }
}

// FragmentStream 在 S: Unpin 时自动 Unpin（因为没有自引用字段）
impl<S: Unpin> Unpin for FragmentStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_fragments() {
        let data = vec![0u8; 200];
        let frags = FragmentStream::<tokio::net::TcpStream>::split_to_fragments(&data, 10, 50);
        assert!(frags.len() >= 4); // 200 / 50 = 4 minimum
        let total: usize = frags.iter().map(|f| f.len()).sum();
        assert_eq!(total, 200);
        for f in &frags {
            assert!(f.len() >= 10 && f.len() <= 50, "fragment size {} not in [10, 50]", f.len());
        }
    }

    #[test]
    fn test_split_small_data() {
        let data = vec![0u8; 5];
        let frags = FragmentStream::<tokio::net::TcpStream>::split_to_fragments(&data, 10, 50);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].len(), 5);
    }

    #[test]
    fn test_split_exact_boundary() {
        let data = vec![0u8; 100];
        let frags = FragmentStream::<tokio::net::TcpStream>::split_to_fragments(&data, 100, 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].len(), 100);
    }
}
