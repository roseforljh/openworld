pub mod crypto;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

use crypto::{AeadCipher, CipherKind, derive_subkey, evp_bytes_to_key};

/// Maximum payload size per AEAD frame (0x3FFF = 16383)
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;

pub struct ShadowsocksOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    cipher_kind: CipherKind,
    key: Vec<u8>,
}

impl ShadowsocksOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;

        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("shadowsocks outbound '{}' missing 'address'", config.tag))?
            .clone();

        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("shadowsocks outbound '{}' missing 'port'", config.tag))?;

        let password = settings
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("shadowsocks outbound '{}' missing 'password'", config.tag))?;

        let method = settings
            .method
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("shadowsocks outbound '{}' missing 'method'", config.tag))?;

        let cipher_kind = CipherKind::from_str(method)?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher_kind.key_len());

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            method = method,
            "shadowsocks outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address,
            server_port: port,
            cipher_kind,
            key,
        })
    }
}

#[async_trait]
impl OutboundHandler for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let server = format!("{}:{}", self.server_addr, self.server_port);
        debug!(target = %session.target, server = %server, "shadowsocks connecting");

        let mut stream = TcpStream::connect(&server).await?;

        // Generate random salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill(&mut salt[..]);

        // Derive subkey for sending direction
        let subkey = derive_subkey(&self.key, &salt, self.cipher_kind.key_len())?;
        let mut encoder = AeadCipher::new(self.cipher_kind, subkey);

        // Send salt
        stream.write_all(&salt).await?;

        // Encode target address in SOCKS5 format
        let mut addr_buf = BytesMut::new();
        session.target.encode_socks5(&mut addr_buf);
        let addr_payload = addr_buf.to_vec();

        // Encrypt and send the first frame (target address)
        write_aead_frame(&mut encoder, &mut stream, &addr_payload).await?;

        debug!(target = %session.target, "shadowsocks handshake complete");

        Ok(Box::new(AeadStream::new(
            stream,
            encoder,
            self.cipher_kind,
            self.key.clone(),
        )))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let server_addr = format!("{}:{}", self.server_addr, self.server_port);
        debug!(local = %socket.local_addr()?, server = %server_addr, "shadowsocks UDP bound");

        Ok(Box::new(ShadowsocksUdpTransport {
            socket: Arc::new(socket),
            server_addr,
            cipher_kind: self.cipher_kind,
            key: self.key.clone(),
        }))
    }
}

/// Write a single AEAD frame: [encrypted(length: 2 BE)][tag] + [encrypted(payload)][tag]
async fn write_aead_frame(
    cipher: &mut AeadCipher,
    writer: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
) -> Result<()> {
    let len = payload.len() as u16;
    let len_bytes = len.to_be_bytes();

    // Encrypt length (2 bytes)
    let encrypted_len = cipher.encrypt(&len_bytes)?;
    writer.write_all(&encrypted_len).await?;

    // Encrypt payload
    let encrypted_payload = cipher.encrypt(payload)?;
    writer.write_all(&encrypted_payload).await?;

    Ok(())
}

/// Read state machine for AEAD stream decryption.
enum ReadState {
    /// Need to read the server salt (decoder not initialized yet)
    ReadSalt {
        salt_buf: Vec<u8>,
        salt_read: usize,
    },
    /// Need to read encrypted length frame (2 + tag_len bytes)
    ReadLength {
        len_buf: Vec<u8>,
        len_read: usize,
    },
    /// Need to read encrypted payload frame (payload_len + tag_len bytes)
    ReadPayload {
        payload_buf: Vec<u8>,
        payload_read: usize,
    },
}

/// Write state machine for AEAD stream encryption.
enum WriteState {
    /// Ready to accept new data
    Ready,
    /// Have encrypted data pending write
    Writing {
        data: Vec<u8>,
        written: usize,
        original_len: usize,
    },
}

/// AEAD stream wrapping a TCP connection for Shadowsocks protocol.
///
/// Write side: encrypts data in AEAD frames.
/// Read side: lazily initializes decoder on first read (reads server salt),
///            then decrypts AEAD frames using a state machine.
pub struct AeadStream {
    inner: TcpStream,
    encoder: AeadCipher,
    decoder: Option<AeadCipher>,
    cipher_kind: CipherKind,
    key: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_state: ReadState,
    write_state: WriteState,
}

impl AeadStream {
    fn new(
        inner: TcpStream,
        encoder: AeadCipher,
        cipher_kind: CipherKind,
        key: Vec<u8>,
    ) -> Self {
        let salt_len = cipher_kind.salt_len();
        Self {
            inner,
            encoder,
            decoder: None,
            cipher_kind,
            key,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::ReadSalt {
                salt_buf: vec![0u8; salt_len],
                salt_read: 0,
            },
            write_state: WriteState::Ready,
        }
    }
}

impl AsyncRead for AeadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // If we have buffered decrypted data, return it
            if this.read_pos < this.read_buf.len() {
                let remaining = &this.read_buf[this.read_pos..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                this.read_pos += to_copy;
                if this.read_pos >= this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match &mut this.read_state {
                ReadState::ReadSalt { salt_buf, salt_read } => {
                    // Read salt bytes from the stream
                    while *salt_read < salt_buf.len() {
                        let mut read_buf = ReadBuf::new(&mut salt_buf[*salt_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading salt",
                                    )));
                                }
                                *salt_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Salt fully read, derive subkey and initialize decoder
                    let subkey = derive_subkey(&this.key, salt_buf, this.cipher_kind.key_len())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                    this.decoder = Some(AeadCipher::new(this.cipher_kind, subkey));

                    // Transition to reading length
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::ReadLength {
                        len_buf: vec![0u8; 2 + tag_len],
                        len_read: 0,
                    };
                }

                ReadState::ReadLength { len_buf, len_read } => {
                    // Read encrypted length frame
                    while *len_read < len_buf.len() {
                        let mut read_buf = ReadBuf::new(&mut len_buf[*len_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading length frame",
                                    )));
                                }
                                *len_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt length
                    let decoder = this.decoder.as_mut().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::Other, "decoder not initialized")
                    })?;

                    let len_plain = decoder.decrypt(len_buf).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })?;

                    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
                    if payload_len > MAX_PAYLOAD_SIZE {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("payload length {} exceeds maximum {}", payload_len, MAX_PAYLOAD_SIZE),
                        )));
                    }

                    // Transition to reading payload
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::ReadPayload {
                        payload_buf: vec![0u8; payload_len + tag_len],
                        payload_read: 0,
                    };
                }

                ReadState::ReadPayload { payload_buf, payload_read } => {
                    // Read encrypted payload frame
                    while *payload_read < payload_buf.len() {
                        let mut read_buf = ReadBuf::new(&mut payload_buf[*payload_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading payload frame",
                                    )));
                                }
                                *payload_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt payload
                    let decoder = this.decoder.as_mut().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::Other, "decoder not initialized")
                    })?;

                    let payload = decoder.decrypt(payload_buf).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })?;

                    // Store decrypted data and transition to HasData
                    this.read_buf = payload;
                    this.read_pos = 0;

                    // Transition to reading next length frame
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::ReadLength {
                        len_buf: vec![0u8; 2 + tag_len],
                        len_read: 0,
                    };

                    // Loop back to return buffered data
                }
            }
        }
    }
}

impl AsyncWrite for AeadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        loop {
            match &mut this.write_state {
                WriteState::Ready => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    // Chunk data to MAX_PAYLOAD_SIZE
                    let chunk_len = buf.len().min(MAX_PAYLOAD_SIZE);
                    let chunk = &buf[..chunk_len];

                    // Encrypt length
                    let len_bytes = (chunk_len as u16).to_be_bytes();
                    let encrypted_len = this.encoder.encrypt(&len_bytes).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })?;

                    // Encrypt payload
                    let encrypted_payload = this.encoder.encrypt(chunk).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })?;

                    // Combine into a single write buffer
                    let mut data = Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
                    data.extend_from_slice(&encrypted_len);
                    data.extend_from_slice(&encrypted_payload);

                    this.write_state = WriteState::Writing {
                        data,
                        written: 0,
                        original_len: chunk_len,
                    };
                }

                WriteState::Writing { data, written, original_len } => {
                    while *written < data.len() {
                        match Pin::new(&mut this.inner).poll_write(cx, &data[*written..]) {
                            Poll::Ready(Ok(n)) => {
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::WriteZero,
                                        "write returned 0",
                                    )));
                                }
                                *written += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // All encrypted data written
                    let original_len = *original_len;
                    this.write_state = WriteState::Ready;
                    return Poll::Ready(Ok(original_len));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Shadowsocks UDP transport.
///
/// Each UDP packet is independently encrypted:
/// Send: [random salt][encrypted(socks5_addr + payload)]
/// Recv: [salt][encrypted(socks5_addr + payload)]
struct ShadowsocksUdpTransport {
    socket: Arc<UdpSocket>,
    server_addr: String,
    cipher_kind: CipherKind,
    key: Vec<u8>,
}

#[async_trait]
impl UdpTransport for ShadowsocksUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        // Generate random salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill(&mut salt[..]);

        // Derive subkey
        let subkey = derive_subkey(&self.key, &salt, self.cipher_kind.key_len())?;
        let mut cipher = AeadCipher::new(self.cipher_kind, subkey);

        // Build payload: socks5_addr + data
        let mut payload_buf = BytesMut::new();
        packet.addr.encode_socks5(&mut payload_buf);
        payload_buf.put_slice(&packet.data);

        // Encrypt the entire payload as one AEAD operation
        let encrypted = cipher.encrypt(&payload_buf)?;

        // Build final packet: salt + encrypted
        let mut out = Vec::with_capacity(salt_len + encrypted.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&encrypted);

        // Resolve server address and send
        let addr: std::net::SocketAddr = tokio::net::lookup_host(&self.server_addr)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve server address: {}", self.server_addr))?;

        self.socket.send_to(&out, addr).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let (n, _from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);

        let salt_len = self.cipher_kind.salt_len();
        if buf.len() < salt_len {
            bail!("UDP packet too short for salt: {} bytes", buf.len());
        }

        let salt = &buf[..salt_len];
        let encrypted = &buf[salt_len..];

        // Derive subkey and decrypt
        let subkey = derive_subkey(&self.key, salt, self.cipher_kind.key_len())?;
        let mut cipher = AeadCipher::new(self.cipher_kind, subkey);
        let decrypted = cipher.decrypt(encrypted)?;

        // Parse socks5 address from decrypted payload
        let (addr, consumed) = Address::parse_socks5_udp_addr(&decrypted)?;
        let data = decrypted[consumed..].to_vec();

        Ok(UdpPacket {
            addr,
            data: Bytes::from(data),
        })
    }
}
