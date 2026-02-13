use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::RwLock;

use crate::common::{Address, ProxyStream, UdpPacket, UdpTransport};
use crate::config::types::InboundConfig;
use crate::proxy::outbound::shadowsocks::crypto::{
    derive_subkey, evp_bytes_to_key, ss2022_password_to_key, AeadCipher, CipherKind,
};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

/// SSM 用户信息（API 返回用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsmUserInfo {
    pub name: String,
    pub traffic_up: u64,
    pub traffic_down: u64,
}

/// Shadowsocks 用户（支持动态管理）
pub struct ShadowsocksUser {
    pub name: String,
    pub key: Vec<u8>,
    /// 上行流量（字节）
    pub traffic_up: AtomicU64,
    /// 下行流量（字节）
    pub traffic_down: AtomicU64,
}

impl ShadowsocksUser {
    pub fn new(name: String, key: Vec<u8>) -> Self {
        Self {
            name,
            key,
            traffic_up: AtomicU64::new(0),
            traffic_down: AtomicU64::new(0),
        }
    }
}

pub struct ShadowsocksInbound {
    tag: String,
    cipher_kind: CipherKind,
    users: Arc<RwLock<Vec<ShadowsocksUser>>>,
}

impl ShadowsocksInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let method = config
            .settings
            .method
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("shadowsocks inbound '{}' missing 'settings.method'", config.tag))?;

        let cipher_kind = CipherKind::parse(method)?;

        let mut users = Vec::new();

        if let Some(password) = config.settings.password.as_ref() {
            users.push(ShadowsocksUser::new(
                "default".to_string(),
                derive_master_key(cipher_kind, password)?,
            ));
        }

        if let Some(raw_users) = config.settings.users.as_ref() {
            for (idx, raw_user) in raw_users.iter().enumerate() {
                let user_method = raw_user
                    .method
                    .as_deref()
                    .unwrap_or(method);
                let user_cipher_kind = CipherKind::parse(user_method)?;
                if user_cipher_kind != cipher_kind {
                    anyhow::bail!(
                        "invalid shadowsocks user #{}: method '{}' mismatches inbound method '{}'",
                        idx,
                        user_method,
                        method
                    );
                }
                let name = raw_user.password.chars().take(8).collect::<String>();
                users.push(ShadowsocksUser::new(
                    format!("user_{}", name),
                    derive_master_key(user_cipher_kind, &raw_user.password)
                        .map_err(|e| anyhow::anyhow!("invalid shadowsocks user #{}: {}", idx, e))?,
                ));
            }
        }

        if users.is_empty() {
            anyhow::bail!(
                "shadowsocks inbound '{}' requires 'settings.password' or non-empty 'settings.users'",
                config.tag
            );
        }

        Ok(Self {
            tag: config.tag.clone(),
            cipher_kind,
            users: Arc::new(RwLock::new(users)),
        })
    }

    // ========== SSM API 方法 ==========

    /// 获取 cipher_kind
    pub fn cipher_kind(&self) -> CipherKind {
        self.cipher_kind
    }

    /// 添加用户
    pub async fn add_user(&self, name: String, password: &str) -> Result<()> {
        let key = derive_master_key(self.cipher_kind, password)?;
        let mut users = self.users.write().await;
        // 检查名称是否已存在
        if users.iter().any(|u| u.name == name) {
            anyhow::bail!("用户 '{}' 已存在", name);
        }
        users.push(ShadowsocksUser::new(name, key));
        Ok(())
    }

    /// 删除用户
    pub async fn remove_user(&self, name: &str) -> bool {
        let mut users = self.users.write().await;
        let len_before = users.len();
        users.retain(|u| u.name != name);
        users.len() < len_before
    }

    /// 列出所有用户及流量
    pub async fn list_users(&self) -> Vec<SsmUserInfo> {
        let users = self.users.read().await;
        users.iter().map(|u| SsmUserInfo {
            name: u.name.clone(),
            traffic_up: u.traffic_up.load(Ordering::Relaxed),
            traffic_down: u.traffic_down.load(Ordering::Relaxed),
        }).collect()
    }

    /// 重置指定用户流量
    pub async fn reset_user_traffic(&self, name: &str) -> bool {
        let users = self.users.read().await;
        if let Some(u) = users.iter().find(|u| u.name == name) {
            u.traffic_up.store(0, Ordering::Relaxed);
            u.traffic_down.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// 获取用户总数
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
    }

}

fn derive_master_key(cipher_kind: CipherKind, password: &str) -> Result<Vec<u8>> {
    match cipher_kind {
        CipherKind::Aes128Gcm2022
        | CipherKind::Aes256Gcm2022
        | CipherKind::ChaCha20Poly1305_2022 => {
            ss2022_password_to_key(password, cipher_kind.key_len())
        }
        _ => Ok(evp_bytes_to_key(password.as_bytes(), cipher_kind.key_len())),
    }
}

const MAX_PAYLOAD_SIZE: usize = 0x3FFF;

#[async_trait]
impl InboundHandler for ShadowsocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, mut stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let salt_len = self.cipher_kind.salt_len();
        let tag_len = self.cipher_kind.tag_len();

        let mut salt = vec![0u8; salt_len];
        stream.read_exact(&mut salt).await?;

        let mut len_frame = vec![0u8; 2 + tag_len];
        stream.read_exact(&mut len_frame).await?;

        let mut selected: Option<(Vec<u8>, usize)> = None;
        {
            let users = self.users.read().await;
            for user in users.iter() {
                let mut decoder = match derive_subkey(&user.key, &salt, self.cipher_kind.key_len()) {
                    Ok(subkey) => AeadCipher::new(self.cipher_kind, subkey),
                    Err(_) => continue,
                };

                let len_plain = match decoder.decrypt(&len_frame) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if len_plain.len() < 2 {
                    continue;
                }

                let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
                selected = Some((user.key.clone(), payload_len));
                break;
            }
        } // release read lock

        let (master_key, payload_len) =
            selected.ok_or_else(|| anyhow::anyhow!("shadowsocks inbound '{}' authentication failed", self.tag))?;

        let mut payload_frame = vec![0u8; payload_len + tag_len];
        stream.read_exact(&mut payload_frame).await?;

        let mut decoder = AeadCipher::new(
            self.cipher_kind,
            derive_subkey(&master_key, &salt, self.cipher_kind.key_len())?,
        );
        let _ = decoder.decrypt(&len_frame)?;
        let payload = decoder.decrypt(&payload_frame)?;

        // Server → Client: send a fresh server salt, derive encoder from it
        let mut server_salt = vec![0u8; salt_len];
        rand::Rng::fill(&mut rand::thread_rng(), &mut server_salt[..]);
        stream.write_all(&server_salt).await?;

        let encoder_subkey = derive_subkey(&master_key, &server_salt, self.cipher_kind.key_len())?;
        let encoder = AeadCipher::new(self.cipher_kind, encoder_subkey);

        let (target, consumed) = Address::parse_socks5_udp_addr(&payload)?;
        let first_udp_payload = payload[consumed..].to_vec();

        let aead_stream: ProxyStream = Box::new(ShadowsocksAeadStream::new(
            stream,
            self.cipher_kind,
            encoder,
            decoder,
        ));

        // UoT auto-detection: handshake payload contains target + data.
        if !first_udp_payload.is_empty() {
            let (control_rx, control_tx) = tokio::io::duplex(1);
            let transport = ShadowsocksUotTransport::new(
                aead_stream,
                target.clone(),
                first_udp_payload,
                control_tx,
            );

            let session = Session {
                target,
                source: Some(source),
                inbound_tag: self.tag.clone(),
                network: Network::Udp,
                sniff: false,
                detected_protocol: None,
            };

            return Ok(InboundResult {
                session,
                stream: Box::new(control_rx),
                udp_transport: Some(Box::new(transport)),
            });
        }

        let session = Session {
            target,
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network: Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };

        Ok(InboundResult {
            session,
            stream: aead_stream,
            udp_transport: None,
        })
    }
}

enum ReadState {
    Length { len_buf: Vec<u8>, len_read: usize },
    Payload { payload_buf: Vec<u8>, payload_read: usize },
}

enum WriteState {
    Ready,
    Writing {
        data: Vec<u8>,
        written: usize,
        original_len: usize,
    },
}

struct ShadowsocksAeadStream {
    inner: ProxyStream,
    cipher_kind: CipherKind,
    encoder: AeadCipher,
    decoder: AeadCipher,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_state: ReadState,
    write_state: WriteState,
}

impl ShadowsocksAeadStream {
    fn new(inner: ProxyStream, cipher_kind: CipherKind, encoder: AeadCipher, decoder: AeadCipher) -> Self {
        let tag_len = cipher_kind.tag_len();
        Self {
            inner,
            cipher_kind,
            encoder,
            decoder,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::Length {
                len_buf: vec![0u8; 2 + tag_len],
                len_read: 0,
            },
            write_state: WriteState::Ready,
        }
    }
}

impl AsyncRead for ShadowsocksAeadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
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
                ReadState::Length { len_buf, len_read } => {
                    while *len_read < len_buf.len() {
                        let mut rb = ReadBuf::new(&mut len_buf[*len_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading shadowsocks length frame",
                                    )));
                                }
                                *len_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let len_plain = this
                        .decoder
                        .decrypt(len_buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    if len_plain.len() < 2 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid shadowsocks length frame",
                        )));
                    }

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
                    while *payload_read < payload_buf.len() {
                        let mut rb = ReadBuf::new(&mut payload_buf[*payload_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading shadowsocks payload frame",
                                    )));
                                }
                                *payload_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let payload = this
                        .decoder
                        .decrypt(payload_buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    this.read_buf = payload;
                    this.read_pos = 0;

                    let tag_len = this.cipher_kind.tag_len();
                    this.read_state = ReadState::Length {
                        len_buf: vec![0u8; 2 + tag_len],
                        len_read: 0,
                    };
                }
            }
        }
    }
}

impl AsyncWrite for ShadowsocksAeadStream {
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

                    let chunk_len = buf.len().min(MAX_PAYLOAD_SIZE);
                    let chunk = &buf[..chunk_len];
                    let len_plain = (chunk_len as u16).to_be_bytes();

                    let encrypted_len = this
                        .encoder
                        .encrypt(&len_plain)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    let encrypted_payload = this
                        .encoder
                        .encrypt(chunk)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    let mut data = Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
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

                    let n = *original_len;
                    this.write_state = WriteState::Ready;
                    return Poll::Ready(Ok(n));
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

struct ShadowsocksUotTransport {
    stream: Arc<tokio::sync::Mutex<ProxyStream>>,
    first_packet: tokio::sync::Mutex<Option<UdpPacket>>,
    control_notifier: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
}

impl ShadowsocksUotTransport {
    fn new(
        stream: ProxyStream,
        first_addr: Address,
        first_data: Vec<u8>,
        control_notifier: tokio::io::DuplexStream,
    ) -> Self {
        Self {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            first_packet: tokio::sync::Mutex::new(Some(UdpPacket {
                addr: first_addr,
                data: bytes::Bytes::from(first_data),
            })),
            control_notifier: tokio::sync::Mutex::new(Some(control_notifier)),
        }
    }

    async fn notify_closed(&self) {
        let mut guard = self.control_notifier.lock().await;
        let _ = guard.take();
    }
}

#[async_trait]
impl UdpTransport for ShadowsocksUotTransport {
    async fn send(&self, packet: UdpPacket) -> Result<()> {
        let mut payload = bytes::BytesMut::with_capacity(32 + packet.data.len());
        packet.addr.encode_socks5(&mut payload);
        payload.extend_from_slice(&packet.data);

        let len = payload.len();
        if len > u16::MAX as usize {
            anyhow::bail!("UoT packet too large: {}", len);
        }

        let mut stream = self.stream.lock().await;
        if let Err(e) = stream.write_all(&(len as u16).to_be_bytes()).await {
            self.notify_closed().await;
            return Err(e.into());
        }
        if let Err(e) = stream.write_all(&payload).await {
            self.notify_closed().await;
            return Err(e.into());
        }

        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        if let Some(pkt) = self.first_packet.lock().await.take() {
            return Ok(pkt);
        }

        let mut len_buf = [0u8; 2];
        let mut stream = self.stream.lock().await;
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            self.notify_closed().await;
            return Err(e.into());
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut payload).await {
            self.notify_closed().await;
            return Err(e.into());
        }

        let (addr, consumed) = Address::parse_socks5_udp_addr(&payload)?;
        Ok(UdpPacket {
            addr,
            data: bytes::Bytes::from(payload[consumed..].to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{InboundSettings, ShadowsocksUserConfig, SniffingConfig};

    fn make_inbound(method: &str, password: &str) -> InboundConfig {
        InboundConfig {
            tag: "ss-in".to_string(),
            protocol: "shadowsocks".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 8388,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                method: Some(method.to_string()),
                password: Some(password.to_string()),
                users: None,
                ..Default::default()
            },
            max_connections: None,
        }
    }

    #[test]
    fn inbound_new_accepts_legacy_method() {
        let cfg = make_inbound("aes-256-gcm", "pass");
        let inbound = ShadowsocksInbound::new(&cfg).unwrap();
        assert_eq!(inbound.tag(), "ss-in");
    }

    #[test]
    fn inbound_new_accepts_2022_method() {
        let cfg = make_inbound("2022-blake3-aes-128-gcm", "1234567890abcdef");
        let inbound = ShadowsocksInbound::new(&cfg).unwrap();
        assert_eq!(inbound.tag(), "ss-in");
    }

    #[test]
    fn inbound_new_2022_bad_key_len_fails() {
        let cfg = make_inbound("aes-128-gcm-2022", "short");
        assert!(ShadowsocksInbound::new(&cfg).is_err());
    }

    #[test]
    fn inbound_new_accepts_users_without_root_password() {
        let cfg = InboundConfig {
            tag: "ss-in".to_string(),
            protocol: "shadowsocks".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 8388,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                method: Some("aes-128-gcm".to_string()),
                password: None,
                users: Some(vec![ShadowsocksUserConfig {
                    password: "user-pass".to_string(),
                    method: None,
                }]),
                ..Default::default()
            },
            max_connections: None,
        };
        let inbound = ShadowsocksInbound::new(&cfg).unwrap();
        assert_eq!(inbound.tag(), "ss-in");
        assert_eq!(inbound.users.try_read().unwrap().len(), 1);
    }

    #[test]
    fn inbound_new_requires_password_or_users() {
        let cfg = InboundConfig {
            tag: "ss-in".to_string(),
            protocol: "shadowsocks".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 8388,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                method: Some("aes-128-gcm".to_string()),
                password: None,
                users: None,
                ..Default::default()
            },
            max_connections: None,
        };
        assert!(ShadowsocksInbound::new(&cfg).is_err());
    }

    #[test]
    fn inbound_new_rejects_user_method_mismatch() {
        let cfg = InboundConfig {
            tag: "ss-in".to_string(),
            protocol: "shadowsocks".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 8388,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                method: Some("aes-128-gcm".to_string()),
                password: None,
                users: Some(vec![ShadowsocksUserConfig {
                    password: "1234567890abcdef".to_string(),
                    method: Some("aes-128-gcm-2022".to_string()),
                }]),
                ..Default::default()
            },
            max_connections: None,
        };
        assert!(ShadowsocksInbound::new(&cfg).is_err());
    }
}
