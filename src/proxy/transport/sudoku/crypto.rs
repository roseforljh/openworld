/// AEAD 加密流
///
/// 在 Sudoku 混淆层之上提供 AEAD 加密，支持：
/// - AES-128-GCM
/// - ChaCha20-Poly1305
/// - none（透传，依赖 Sudoku 混淆层自身安全性）
///
/// 帧格式：[2 字节长度][payload][16 字节 tag]
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TAG_SIZE: usize = 16;
const MAX_PAYLOAD_SIZE: usize = 16384;

enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    ChaCha20(ChaCha20Poly1305),
    None,
}

pub struct AeadStream<S> {
    inner: S,
    cipher: AeadCipher,
    write_nonce: u64,
    read_nonce: u64,
    /// 读取状态
    read_pending: Vec<u8>,
    read_state: ReadState,
}

enum ReadState {
    /// 等待读取 2 字节长度头
    ReadingLength { buf: [u8; 2], offset: usize },
    /// 等待读取 payload + tag
    ReadingPayload { remaining: usize, buf: Vec<u8> },
}

impl<S> AeadStream<S> {
    pub fn new(inner: S, key_material: &str, method: &str) -> Result<Self, String> {
        let cipher = match method {
            "aes-128-gcm" => {
                let key = derive_key(key_material, 16);
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
                AeadCipher::Aes128Gcm(cipher)
            }
            "chacha20-poly1305" => {
                let key = derive_key(key_material, 32);
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
                AeadCipher::ChaCha20(cipher)
            }
            "none" => AeadCipher::None,
            _ => return Err(format!("不支持的 AEAD 方法: {}", method)),
        };

        Ok(AeadStream {
            inner,
            cipher,
            write_nonce: 0,
            read_nonce: 0,
            read_pending: Vec::new(),
            read_state: ReadState::ReadingLength {
                buf: [0; 2],
                offset: 0,
            },
        })
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

fn derive_key(material: &str, len: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    let hash = hasher.finalize();
    hash[..len].to_vec()
}

fn make_nonce(counter: u64, nonce_size: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; nonce_size];
    let bytes = counter.to_le_bytes();
    let copy_len = std::cmp::min(bytes.len(), nonce_size);
    nonce[..copy_len].copy_from_slice(&bytes[..copy_len]);
    nonce
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AeadStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        let payload = if buf.len() > MAX_PAYLOAD_SIZE {
            &buf[..MAX_PAYLOAD_SIZE]
        } else {
            buf
        };

        let encrypted = match &this.cipher {
            AeadCipher::None => {
                // 无加密：直接写长度 + 数据
                let mut frame = Vec::with_capacity(2 + payload.len());
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                frame.extend_from_slice(payload);
                frame
            }
            AeadCipher::Aes128Gcm(cipher) => {
                let nonce_bytes = make_nonce(this.write_nonce, 12);
                this.write_nonce += 1;
                let nonce = GenericArray::from_slice(&nonce_bytes);
                match cipher.encrypt(nonce, payload) {
                    Ok(ciphertext) => {
                        let mut frame = Vec::with_capacity(2 + ciphertext.len());
                        frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                        frame.extend_from_slice(&ciphertext);
                        frame
                    }
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "AEAD 加密失败",
                        )));
                    }
                }
            }
            AeadCipher::ChaCha20(cipher) => {
                let nonce_bytes = make_nonce(this.write_nonce, 12);
                this.write_nonce += 1;
                let nonce = GenericArray::from_slice(&nonce_bytes);
                match cipher.encrypt(nonce, payload) {
                    Ok(ciphertext) => {
                        let mut frame = Vec::with_capacity(2 + ciphertext.len());
                        frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                        frame.extend_from_slice(&ciphertext);
                        frame
                    }
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "AEAD 加密失败",
                        )));
                    }
                }
            }
        };

        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(payload.len())),
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

impl<S: AsyncRead + Unpin> AsyncRead for AeadStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 返回 pending 数据
        if !this.read_pending.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.read_pending.len());
            buf.put_slice(&this.read_pending[..n]);
            this.read_pending.drain(..n);
            return Poll::Ready(Ok(()));
        }

        loop {
            match &mut this.read_state {
                ReadState::ReadingLength {
                    buf: len_buf,
                    offset,
                } => {
                    while *offset < 2 {
                        let mut tmp_buf = [0u8; 2];
                        let mut rb = ReadBuf::new(&mut tmp_buf[..2 - *offset]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let filled = rb.filled();
                                if filled.is_empty() {
                                    return Poll::Ready(Ok(())); // EOF
                                }
                                for &b in filled {
                                    len_buf[*offset] = b;
                                    *offset += 1;
                                }
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let frame_len = u16::from_be_bytes(*len_buf) as usize;
                    if frame_len == 0 || frame_len > MAX_PAYLOAD_SIZE + TAG_SIZE + 64 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("无效帧长度: {}", frame_len),
                        )));
                    }

                    this.read_state = ReadState::ReadingPayload {
                        remaining: frame_len,
                        buf: Vec::with_capacity(frame_len),
                    };
                }
                ReadState::ReadingPayload {
                    remaining,
                    buf: frame_buf,
                } => {
                    while *remaining > 0 {
                        let mut tmp = vec![0u8; *remaining];
                        let mut rb = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let filled = rb.filled();
                                if filled.is_empty() {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "AEAD 帧读取中断",
                                    )));
                                }
                                frame_buf.extend_from_slice(filled);
                                *remaining -= filled.len();
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // 解密
                    let frame_data = std::mem::take(frame_buf);
                    this.read_state = ReadState::ReadingLength {
                        buf: [0; 2],
                        offset: 0,
                    };

                    let decrypted = match &this.cipher {
                        AeadCipher::None => frame_data,
                        AeadCipher::Aes128Gcm(cipher) => {
                            let nonce_bytes = make_nonce(this.read_nonce, 12);
                            this.read_nonce += 1;
                            let nonce = GenericArray::from_slice(&nonce_bytes);
                            cipher.decrypt(nonce, frame_data.as_ref()).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "AEAD 解密失败")
                            })?
                        }
                        AeadCipher::ChaCha20(cipher) => {
                            let nonce_bytes = make_nonce(this.read_nonce, 12);
                            this.read_nonce += 1;
                            let nonce = GenericArray::from_slice(&nonce_bytes);
                            cipher.decrypt(nonce, frame_data.as_ref()).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "AEAD 解密失败")
                            })?
                        }
                    };

                    let n = std::cmp::min(buf.remaining(), decrypted.len());
                    buf.put_slice(&decrypted[..n]);
                    if n < decrypted.len() {
                        this.read_pending.extend_from_slice(&decrypted[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
