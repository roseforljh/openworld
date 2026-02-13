/// Sudoku 混淆流
///
/// 包装底层流，对写入数据进行 Sudoku 编码（每字节 → 4 字节提示 + padding），
/// 对读取数据进行解码（过滤 padding → 收集 4 提示 → 查表还原）。
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::table::Table;

/// 24 种 4 元素排列（用于随机化提示发送顺序）
const PERM4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

pub struct SudokuStream<S> {
    inner: S,
    table: Arc<Table>,
    rng: ChaCha8Rng,
    padding_threshold: u64,
    /// 读取解码状态
    hint_buf: Vec<u8>,
    pending_data: Vec<u8>,
    /// 写入编码缓冲
    write_buf: Vec<u8>,
}

impl<S> SudokuStream<S> {
    pub fn new(inner: S, table: Arc<Table>, padding_min: u8, padding_max: u8) -> Self {
        let mut seed_bytes = [0u8; 8];
        if rand::Rng::try_fill(&mut rand::thread_rng(), &mut seed_bytes).is_err() {
            seed_bytes = [42; 8];
        }
        let seed = u64::from_be_bytes(seed_bytes);
        let rng = ChaCha8Rng::seed_from_u64(seed);
        let threshold = pick_padding_threshold(padding_min, padding_max);

        SudokuStream {
            inner,
            table,
            rng,
            padding_threshold: threshold,
            hint_buf: Vec::with_capacity(4),
            pending_data: Vec::with_capacity(4096),
            write_buf: Vec::with_capacity(32 * 1024),
        }
    }

    /// 获取底层流的引用
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// 获取底层流的可变引用
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// 消费 wrapper，返回底层流
    pub fn into_inner(self) -> S {
        self.inner
    }
}

fn pick_padding_threshold(min: u8, max: u8) -> u64 {
    if max == 0 {
        return 0;
    }
    let mid = ((min as u64) + (max as u64)) / 2;
    // 概率阈值：mid% 概率插入 padding
    (u64::MAX / 100) * mid
}

fn should_pad(rng: &mut ChaCha8Rng, threshold: u64) -> bool {
    if threshold == 0 {
        return false;
    }
    rand::Rng::gen::<u64>(rng) < threshold
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SudokuStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        // 将输入数据编码到 write_buf
        this.write_buf.clear();
        let pads = &this.table.padding_pool;
        let pad_len = pads.len();

        for &b in buf {
            // 前置 padding
            if should_pad(&mut this.rng, this.padding_threshold) && pad_len > 0 {
                let idx = rand::Rng::gen_range(&mut this.rng, 0..pad_len);
                this.write_buf.push(pads[idx]);
            }

            // 编码字节
            let hints = this.table.encode_byte(b, &mut this.rng);
            let perm_idx = rand::Rng::gen_range(&mut this.rng, 0..24);
            let perm = &PERM4[perm_idx];

            for &idx in perm {
                // 提示间 padding
                if should_pad(&mut this.rng, this.padding_threshold) && pad_len > 0 {
                    let pidx = rand::Rng::gen_range(&mut this.rng, 0..pad_len);
                    this.write_buf.push(pads[pidx]);
                }
                this.write_buf.push(hints[idx]);
            }
        }

        // 尾部 padding
        if should_pad(&mut this.rng, this.padding_threshold) && pad_len > 0 {
            let idx = rand::Rng::gen_range(&mut this.rng, 0..pad_len);
            this.write_buf.push(pads[idx]);
        }

        // 写入底层流
        let inner = Pin::new(&mut this.inner);
        match inner.poll_write(cx, &this.write_buf) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SudokuStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 如果有 pending 数据，先返回
        if !this.pending_data.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.pending_data.len());
            buf.put_slice(&this.pending_data[..n]);
            this.pending_data.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // 从底层读取原始数据
        let mut raw_buf = [0u8; 32 * 1024];
        let mut raw_read_buf = ReadBuf::new(&mut raw_buf);

        loop {
            raw_read_buf.clear();
            match Pin::new(&mut this.inner).poll_read(cx, &mut raw_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = raw_read_buf.filled();
                    if filled.is_empty() {
                        // EOF
                        return Poll::Ready(Ok(()));
                    }

                    // 解码：过滤 padding，收集提示
                    for &b in filled {
                        if !this.table.layout.is_hint(b) {
                            continue; // padding，跳过
                        }

                        this.hint_buf.push(b);
                        if this.hint_buf.len() == 4 {
                            let hints = [
                                this.hint_buf[0],
                                this.hint_buf[1],
                                this.hint_buf[2],
                                this.hint_buf[3],
                            ];
                            match this.table.decode_hints(hints) {
                                Some(val) => this.pending_data.push(val),
                                None => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "INVALID_SUDOKU_MAP_MISS",
                                    )));
                                }
                            }
                            this.hint_buf.clear();
                        }
                    }

                    if !this.pending_data.is_empty() {
                        let n = std::cmp::min(buf.remaining(), this.pending_data.len());
                        buf.put_slice(&this.pending_data[..n]);
                        this.pending_data.drain(..n);
                        return Poll::Ready(Ok(()));
                    }
                    // 继续读取更多数据
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
