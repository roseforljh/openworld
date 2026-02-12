pub mod crypto;

use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

use crypto::{derive_identity_subkey_2022, derive_subkey, derive_subkey_2022, evp_bytes_to_key, is_aead_2022, ss2022_password_to_key, AeadCipher, CipherKind};

/// Maximum payload size per AEAD frame (0x3FFF = 16383)
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;

struct Sip003Runtime {
    child: Child,
    local_addr: String,
}

pub struct ShadowsocksOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    cipher_kind: CipherKind,
    key: Vec<u8>,
    /// iPSK (identity PSK) for SIP022 multi-user
    identity_key: Option<Vec<u8>>,
    plugin: Option<String>,
    plugin_opts: Option<String>,
    plugin_runtime: Option<Arc<Mutex<Sip003Runtime>>>,
    dialer_config: Option<DialerConfig>,
}

impl ShadowsocksOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;

        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("shadowsocks outbound '{}' missing 'address'", config.tag)
            })?
            .clone();

        let port = settings.port.ok_or_else(|| {
            anyhow::anyhow!("shadowsocks outbound '{}' missing 'port'", config.tag)
        })?;

        let password = settings.password.as_ref().ok_or_else(|| {
            anyhow::anyhow!("shadowsocks outbound '{}' missing 'password'", config.tag)
        })?;

        let method = settings.method.as_ref().ok_or_else(|| {
            anyhow::anyhow!("shadowsocks outbound '{}' missing 'method'", config.tag)
        })?;

        let cipher_kind = CipherKind::parse(method)?;
        let key = match cipher_kind {
            CipherKind::Aes128Gcm2022
            | CipherKind::Aes256Gcm2022
            | CipherKind::ChaCha20Poly1305_2022 => {
                ss2022_password_to_key(password, cipher_kind.key_len())?
            }
            _ => evp_bytes_to_key(password.as_bytes(), cipher_kind.key_len()),
        };

        // Parse iPSK (identity key) for SIP022 multi-user
        let identity_key = if let Some(ref ipsk) = settings.identity_key {
            if !is_aead_2022(cipher_kind) {
                bail!(
                    "shadowsocks outbound '{}': identity_key requires a 2022 cipher method",
                    config.tag
                );
            }
            Some(ss2022_password_to_key(ipsk, cipher_kind.key_len())?)
        } else {
            None
        };

        let plugin = settings.plugin.clone();
        let plugin_opts = settings.plugin_opts.clone();
        let plugin_runtime = if let Some(plugin_bin) = plugin.as_ref() {
            let runtime = spawn_sip003_runtime(
                plugin_bin,
                plugin_opts.as_deref(),
                &address,
                port,
            )?;

            let remote_addr = format!("{}:{}", address, port);
            debug!(
                tag = config.tag,
                plugin = plugin_bin,
                local_addr = %runtime.local_addr,
                remote_addr = %remote_addr,
                "shadowsocks SIP003 plugin started"
            );

            Some(Arc::new(Mutex::new(runtime)))
        } else {
            None
        };

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            method = method,
            plugin = ?plugin,
            "shadowsocks outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address,
            server_port: port,
            cipher_kind,
            key,
            identity_key,
            plugin,
            plugin_opts,
            plugin_runtime,
            dialer_config: settings.dialer.clone(),
        })
    }
}

impl Drop for ShadowsocksOutbound {
    fn drop(&mut self) {
        if let Some(runtime) = &self.plugin_runtime {
            if let Ok(mut guard) = runtime.lock() {
                let _ = guard.child.kill();
                let _ = guard.child.wait();
            }
        }
    }
}

fn pick_free_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn build_sip003_command(
    plugin_bin: &str,
    plugin_opts: Option<&str>,
    remote_host: &str,
    remote_port: u16,
    local_host: &str,
    local_port: u16,
) -> Command {
    let mut cmd = Command::new(plugin_bin);
    let args = parse_plugin_options(plugin_opts);
    cmd.args(args)
        .env("SS_REMOTE_HOST", remote_host)
        .env("SS_REMOTE_PORT", remote_port.to_string())
        .env("SS_LOCAL_HOST", local_host)
        .env("SS_LOCAL_PORT", local_port.to_string())
        .env("SS_PLUGIN_OPTIONS", plugin_opts.unwrap_or(""))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

fn spawn_sip003_runtime(
    plugin_bin: &str,
    plugin_opts: Option<&str>,
    remote_host: &str,
    remote_port: u16,
) -> Result<Sip003Runtime> {
    let local_port = pick_free_local_port()?;
    let local_host = "127.0.0.1";
    let local_addr = format!("{}:{}", local_host, local_port);

    let mut cmd = build_sip003_command(
        plugin_bin,
        plugin_opts,
        remote_host,
        remote_port,
        local_host,
        local_port,
    );

    let mut child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!(
            "failed to spawn SIP003 plugin '{}': {}",
            plugin_bin,
            e
        )
    })?;

    std::thread::sleep(Duration::from_millis(80));
    if let Some(status) = child.try_wait()? {
        anyhow::bail!(
            "SIP003 plugin '{}' exited early with status {}",
            plugin_bin,
            status
        );
    }

    Ok(Sip003Runtime { child, local_addr })
}

fn parse_plugin_options(plugin_opts: Option<&str>) -> Vec<String> {
    plugin_opts
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn ensure_plugin_runtime_alive(
    runtime: &Arc<Mutex<Sip003Runtime>>,
    plugin_bin: &str,
    plugin_opts: Option<&str>,
    remote_host: &str,
    remote_port: u16,
) -> Result<String> {
    let mut guard = runtime
        .lock()
        .map_err(|_| anyhow::anyhow!("failed to lock SIP003 plugin runtime"))?;

    if let Some(status) = guard.child.try_wait()? {
        debug!(status = %status, plugin = plugin_bin, "SIP003 plugin exited, respawning");
        *guard = spawn_sip003_runtime(plugin_bin, plugin_opts, remote_host, remote_port)?;
    }

    Ok(guard.local_addr.clone())
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
        let (server, use_dialer) = if let (Some(plugin), Some(runtime)) = (&self.plugin, &self.plugin_runtime) {
            let addr = ensure_plugin_runtime_alive(
                runtime,
                plugin,
                self.plugin_opts.as_deref(),
                &self.server_addr,
                self.server_port,
            )?;
            debug!(plugin = plugin, plugin_opts = ?self.plugin_opts, proxy = %addr, "shadowsocks plugin active");
            (addr, false) // Plugin uses local address, no dialer needed
        } else {
            (format!("{}:{}", self.server_addr, self.server_port), true)
        };
        debug!(target = %session.target, server = %server, "shadowsocks connecting");

        let mut stream = if use_dialer {
            let dialer = match &self.dialer_config {
                Some(cfg) => Dialer::new(cfg.clone()),
                None => Dialer::default_dialer(),
            };
            dialer.connect_host(&self.server_addr, self.server_port).await?
        } else {
            TcpStream::connect(&server).await?
        };

        // Generate random salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill(&mut salt[..]);

        // Derive subkey for sending direction
        let subkey = if is_aead_2022(self.cipher_kind) {
            derive_subkey_2022(&self.key, &salt, self.cipher_kind.key_len())?
        } else {
            derive_subkey(&self.key, &salt, self.cipher_kind.key_len())?
        };
        let mut encoder = AeadCipher::new(self.cipher_kind, subkey);

        // Send salt
        stream.write_all(&salt).await?;

        // SIP022: send iPSK identity header if identity_key is set
        if let Some(ref identity_key) = self.identity_key {
            let key_len = self.cipher_kind.key_len();
            let id_subkey = derive_identity_subkey_2022(identity_key, &salt, key_len);
            let mut id_cipher = AeadCipher::new(self.cipher_kind, id_subkey);
            // Identity header payload = user's PSK (first key_len bytes)
            let id_payload = &self.key[..key_len];
            let encrypted_id = id_cipher.encrypt(id_payload)?;
            stream.write_all(&encrypted_id).await?;
        }

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
            identity_key: self.identity_key.clone(),
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
    Salt { salt_buf: Vec<u8>, salt_read: usize },
    /// Need to read encrypted length frame (2 + tag_len bytes)
    Length { len_buf: Vec<u8>, len_read: usize },
    /// Need to read encrypted payload frame (payload_len + tag_len bytes)
    Payload {
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
    fn new(inner: TcpStream, encoder: AeadCipher, cipher_kind: CipherKind, key: Vec<u8>) -> Self {
        let salt_len = cipher_kind.salt_len();
        Self {
            inner,
            encoder,
            decoder: None,
            cipher_kind,
            key,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::Salt {
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
                ReadState::Salt {
                    salt_buf,
                    salt_read,
                } => {
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
                    let subkey = if is_aead_2022(this.cipher_kind) {
                        derive_subkey_2022(&this.key, salt_buf, this.cipher_kind.key_len())
                    } else {
                        derive_subkey(&this.key, salt_buf, this.cipher_kind.key_len())
                    }
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                    this.decoder = Some(AeadCipher::new(this.cipher_kind, subkey));

                    // Transition to reading length
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::Length {
                        len_buf: vec![0u8; 2 + tag_len],
                        len_read: 0,
                    };
                }

                ReadState::Length { len_buf, len_read } => {
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
                    let decoder = this
                        .decoder
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("decoder not initialized"))?;

                    let len_plain = decoder
                        .decrypt(len_buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
                    if payload_len > MAX_PAYLOAD_SIZE {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "payload length {} exceeds maximum {}",
                                payload_len, MAX_PAYLOAD_SIZE
                            ),
                        )));
                    }

                    // Transition to reading payload
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::Payload {
                        payload_buf: vec![0u8; payload_len + tag_len],
                        payload_read: 0,
                    };
                }

                ReadState::Payload {
                    payload_buf,
                    payload_read,
                } => {
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
                    let decoder = this
                        .decoder
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("decoder not initialized"))?;

                    let payload = decoder
                        .decrypt(payload_buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    // Store decrypted data and transition to HasData
                    this.read_buf = payload;
                    this.read_pos = 0;

                    // Transition to reading next length frame
                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::Length {
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
                    let encrypted_len = this
                        .encoder
                        .encrypt(&len_bytes)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    // Encrypt payload
                    let encrypted_payload = this
                        .encoder
                        .encrypt(chunk)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    // Combine into a single write buffer
                    let mut data =
                        Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
                    data.extend_from_slice(&encrypted_len);
                    data.extend_from_slice(&encrypted_payload);

                    this.write_state = WriteState::Writing {
                        data,
                        written: 0,
                        original_len: chunk_len,
                    };
                }

                WriteState::Writing {
                    data,
                    written,
                    original_len,
                } => {
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
    identity_key: Option<Vec<u8>>,
}

#[async_trait]
impl UdpTransport for ShadowsocksUdpTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        // Generate random salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill(&mut salt[..]);

        // Derive subkey
        let subkey = if is_aead_2022(self.cipher_kind) {
            derive_subkey_2022(&self.key, &salt, self.cipher_kind.key_len())?
        } else {
            derive_subkey(&self.key, &salt, self.cipher_kind.key_len())?
        };
        let mut cipher = AeadCipher::new(self.cipher_kind, subkey);

        // Build payload
        let mut payload_buf = BytesMut::new();
        if is_aead_2022(self.cipher_kind) {
            // SIP022 UDP: [type=0x00][timestamp_u64_be][socks5_addr][data]
            payload_buf.put_u8(0x00); // client request type
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            payload_buf.put_u64(ts);
            // padding length = 0 (no padding for outbound client)
            payload_buf.put_u16(0);
        }
        packet.addr.encode_socks5(&mut payload_buf);
        payload_buf.put_slice(&packet.data);

        // Encrypt the entire payload as one AEAD operation
        let encrypted = cipher.encrypt(&payload_buf)?;

        // Build final packet: salt + [identity header] + encrypted
        let mut out = Vec::with_capacity(salt_len + encrypted.len() + 64);
        out.extend_from_slice(&salt);

        // SIP022: send iPSK identity header for UDP
        if let Some(ref identity_key) = self.identity_key {
            let key_len = self.cipher_kind.key_len();
            let id_subkey = derive_identity_subkey_2022(identity_key, &salt, key_len);
            let mut id_cipher = AeadCipher::new(self.cipher_kind, id_subkey);
            let id_payload = &self.key[..key_len];
            let encrypted_id = id_cipher.encrypt(id_payload)?;
            out.extend_from_slice(&encrypted_id);
        }

        out.extend_from_slice(&encrypted);

        // Resolve server address and send
        let addr: std::net::SocketAddr = tokio::net::lookup_host(&self.server_addr)
            .await?
            .next()
            .ok_or_else(|| {
            anyhow::anyhow!("failed to resolve server address: {}", self.server_addr)
        })?;

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
        let subkey = if is_aead_2022(self.cipher_kind) {
            derive_subkey_2022(&self.key, salt, self.cipher_kind.key_len())?
        } else {
            derive_subkey(&self.key, salt, self.cipher_kind.key_len())?
        };
        let mut cipher = AeadCipher::new(self.cipher_kind, subkey);
        let decrypted = cipher.decrypt(encrypted)?;

        // SIP022: skip type header for 2022 ciphers
        let payload_start = if is_aead_2022(self.cipher_kind) {
            // Server response: [type=0x01][timestamp_u64_be][client_session_id_u64_be][padding_len_u16][padding][addr][data]
            // Minimum: 1 + 8 + 8 + 2 = 19 bytes header
            if decrypted.len() < 19 {
                bail!("SIP022 UDP response too short");
            }
            let padding_len = u16::from_be_bytes([decrypted[17], decrypted[18]]) as usize;
            19 + padding_len
        } else {
            0
        };

        // Parse socks5 address from decrypted payload
        let (addr, consumed) = Address::parse_socks5_udp_addr(&decrypted[payload_start..])?;
        let data = decrypted[payload_start + consumed..].to_vec();

        Ok(UdpPacket {
            addr,
            data: Bytes::from(data),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip003_command_sets_required_envs() {
        let cmd = build_sip003_command(
            "plugin-bin",
            Some("mode=websocket;host=example.com"),
            "1.2.3.4",
            8388,
            "127.0.0.1",
            32001,
        );

        let envs: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().to_string(),
                    v?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        assert_eq!(envs.get("SS_REMOTE_HOST").map(String::as_str), Some("1.2.3.4"));
        assert_eq!(envs.get("SS_REMOTE_PORT").map(String::as_str), Some("8388"));
        assert_eq!(envs.get("SS_LOCAL_HOST").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(envs.get("SS_LOCAL_PORT").map(String::as_str), Some("32001"));
        assert_eq!(
            envs.get("SS_PLUGIN_OPTIONS").map(String::as_str),
            Some("mode=websocket;host=example.com")
        );
    }

    #[test]
    fn sip003_command_defaults_empty_plugin_options() {
        let cmd = build_sip003_command("plugin-bin", None, "1.1.1.1", 443, "127.0.0.1", 10000);

        let envs: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().to_string(),
                    v?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        assert_eq!(envs.get("SS_PLUGIN_OPTIONS").map(String::as_str), Some(""));
    }

    #[test]
    fn sip003_command_parses_plugin_options_into_args() {
        let cmd = build_sip003_command(
            "plugin-bin",
            Some("--fast-open --mode websocket"),
            "8.8.8.8",
            8388,
            "127.0.0.1",
            20000,
        );

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert_eq!(args, vec!["--fast-open", "--mode", "websocket"]);
    }

    #[test]
    fn parse_plugin_options_empty() {
        assert!(parse_plugin_options(None).is_empty());
        assert!(parse_plugin_options(Some("   ")).is_empty());
    }

    #[test]
    fn pick_free_local_port_returns_non_zero() {
        let port = pick_free_local_port().unwrap();
        assert_ne!(port, 0);
    }
}
