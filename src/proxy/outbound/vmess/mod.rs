pub mod protocol;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::mux::{MuxManager, MuxTransport, StreamConnector};
use crate::proxy::transport::StreamTransport;
use crate::proxy::{OutboundHandler, Session};

use protocol::{
    SecurityType, VmessChunkCipher, CMD_TCP, MAX_VMESS_CHUNK, VMESS_AEAD_TAG_LEN,
    derive_response_key_iv, parse_response_header,
};

pub struct VmessOutbound {
    tag: String,
    server_addr: Address,
    uuid: [u8; 16],
    security: SecurityType,
    transport: Arc<dyn StreamTransport>,
    mux: Option<Arc<MuxManager>>,
}

impl VmessOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vmess: address is required"))?;
        let port = settings
            .port
            .ok_or_else(|| anyhow::anyhow!("vmess: port is required"))?;
        let uuid_str = settings
            .uuid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vmess: uuid is required"))?;
        let uuid_parsed = uuid_str.parse::<uuid::Uuid>()?;
        let uuid = *uuid_parsed.as_bytes();

        let security = settings
            .method
            .as_deref()
            .map(SecurityType::from_str)
            .unwrap_or(SecurityType::Aes128Gcm);

        let tls_config = settings.effective_tls();
        let transport_config = settings.effective_transport();
        let transport: Arc<dyn StreamTransport> =
            crate::proxy::transport::build_transport_with_dialer(address, port, &transport_config, &tls_config, settings.dialer.clone())?
                .into();

        let server_addr = Address::Domain(address.clone(), port);
        let mux = settings.mux.clone().map(|mux_config| {
            let transport = transport.clone();
            let server_addr = server_addr.clone();
            let connector: StreamConnector = Arc::new(move || {
                let transport = transport.clone();
                let server_addr = server_addr.clone();
                Box::pin(async move { transport.connect(&server_addr).await })
            });
            Arc::new(MuxManager::new(mux_config, connector))
        });

        Ok(Self {
            tag: config.tag.clone(),
            server_addr,
            uuid,
            security,
            transport,
            mux,
        })
    }
}

#[async_trait]
impl OutboundHandler for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(
            tag = self.tag,
            dest = %session.target,
            security = ?self.security,
            "VMess connecting"
        );

        let mut stream = if let Some(mux) = &self.mux {
            mux.open_stream().await?
        } else {
            self.transport.connect(&self.server_addr).await?
        };

        let mut req_body_iv = [0u8; 16];
        let mut req_body_key = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut req_body_iv);
        rand::Rng::fill(&mut rand::thread_rng(), &mut req_body_key);
        let resp_auth: u8 = rand::random();

        let header = protocol::encode_request_header(
            &self.uuid,
            self.security,
            CMD_TCP,
            &session.target,
            &req_body_iv,
            &req_body_key,
            resp_auth,
        )?;

        stream.write_all(&header).await?;
        stream.flush().await?;

        // Read response header (AEAD encrypted: 4 plaintext bytes + 16 tag = 20 bytes)
        let mut resp_header_buf = vec![0u8; 4 + 16];
        stream.read_exact(&mut resp_header_buf).await?;

        let (resp_key, resp_iv) = derive_response_key_iv(&req_body_key, &req_body_iv);
        parse_response_header(&resp_header_buf, &resp_key, &resp_iv, resp_auth)?;

        debug!(
            tag = self.tag,
            dest = %session.target,
            "VMess handshake complete"
        );

        let encoder = VmessChunkCipher::new(self.security, &req_body_key, &req_body_iv);
        let decoder = VmessChunkCipher::new(self.security, &resp_key, &resp_iv);

        Ok(Box::new(VmessAeadStream::new(stream, encoder, decoder, self.security)))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("VMess UDP not yet supported")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

enum VmessReadState {
    Length { len_buf: [u8; 2], len_read: usize },
    Payload { payload_buf: Vec<u8>, payload_read: usize },
}

enum VmessWriteState {
    Ready,
    Writing { data: Vec<u8>, written: usize, original_len: usize },
}

pub struct VmessAeadStream {
    inner: ProxyStream,
    encoder: VmessChunkCipher,
    decoder: VmessChunkCipher,
    security: SecurityType,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_state: VmessReadState,
    write_state: VmessWriteState,
    eof: bool,
}

impl VmessAeadStream {
    pub fn new(
        inner: ProxyStream,
        encoder: VmessChunkCipher,
        decoder: VmessChunkCipher,
        security: SecurityType,
    ) -> Self {
        Self {
            inner,
            encoder,
            decoder,
            security,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: VmessReadState::Length { len_buf: [0u8; 2], len_read: 0 },
            write_state: VmessWriteState::Ready,
            eof: false,
        }
    }

    fn tag_overhead(&self) -> usize {
        match self.security {
            SecurityType::Aes128Gcm | SecurityType::Chacha20Poly1305 => VMESS_AEAD_TAG_LEN,
            _ => 0,
        }
    }
}

impl AsyncRead for VmessAeadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.eof {
            return Poll::Ready(Ok(()));
        }

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
                VmessReadState::Length { len_buf, len_read } => {
                    while *len_read < 2 {
                        let mut rb = ReadBuf::new(&mut len_buf[*len_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    this.eof = true;
                                    return Poll::Ready(Ok(()));
                                }
                                *len_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let raw_len = *len_buf;
                    let chunk_len = this.decoder.decode_length(raw_len) as usize;

                    if chunk_len == 0 {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }

                    this.read_state = VmessReadState::Payload {
                        payload_buf: vec![0u8; chunk_len],
                        payload_read: 0,
                    };
                }
                VmessReadState::Payload { payload_buf, payload_read } => {
                    while *payload_read < payload_buf.len() {
                        let mut rb = ReadBuf::new(&mut payload_buf[*payload_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "VMess payload truncated",
                                    )));
                                }
                                *payload_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let plaintext = this.decoder.decrypt_chunk(payload_buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    this.read_buf = plaintext;
                    this.read_pos = 0;
                    this.read_state = VmessReadState::Length { len_buf: [0u8; 2], len_read: 0 };
                }
            }
        }
    }
}

impl AsyncWrite for VmessAeadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        loop {
            match &mut this.write_state {
                VmessWriteState::Ready => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    let max_plain = MAX_VMESS_CHUNK - this.tag_overhead();
                    let chunk_len = buf.len().min(max_plain);
                    let chunk = &buf[..chunk_len];

                    let data = this.encoder.encrypt_chunk(chunk)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    this.write_state = VmessWriteState::Writing {
                        data,
                        written: 0,
                        original_len: chunk_len,
                    };
                }
                VmessWriteState::Writing { data, written, original_len } => {
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
                    this.write_state = VmessWriteState::Ready;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn vmess_outbound_creation() {
        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            protocol: "vmess".to_string(),
            settings: OutboundSettings {
                address: Some("1.2.3.4".to_string()),
                port: Some(443),
                uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                method: Some("aes-128-gcm".to_string()),
                ..Default::default()
            },
        };
        let outbound = VmessOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "vmess-test");
        assert_eq!(outbound.security, SecurityType::Aes128Gcm);
    }

    #[test]
    fn vmess_outbound_missing_uuid_fails() {
        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            protocol: "vmess".to_string(),
            settings: OutboundSettings {
                address: Some("1.2.3.4".to_string()),
                port: Some(443),
                ..Default::default()
            },
        };
        assert!(VmessOutbound::new(&config).is_err());
    }

    #[test]
    fn vmess_outbound_default_security() {
        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            protocol: "vmess".to_string(),
            settings: OutboundSettings {
                address: Some("1.2.3.4".to_string()),
                port: Some(443),
                uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                ..Default::default()
            },
        };
        let outbound = VmessOutbound::new(&config).unwrap();
        assert_eq!(outbound.security, SecurityType::Aes128Gcm);
    }

    #[test]
    fn vmess_chunk_cipher_encrypt_decrypt_aes128gcm() {
        let key = [0xAAu8; 16];
        let iv = [0xBBu8; 16];
        let plaintext = b"hello vmess aead stream data!";

        let mut enc = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let chunk = enc.encrypt_chunk(plaintext).unwrap();
        assert!(chunk.len() > plaintext.len());

        let mut dec = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let decoded_len = dec.decode_length([chunk[0], chunk[1]]) as usize;
        assert_eq!(decoded_len, plaintext.len() + VMESS_AEAD_TAG_LEN);

        let decrypted = dec.decrypt_chunk(&chunk[2..]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn vmess_chunk_cipher_encrypt_decrypt_chacha20() {
        let key = [0xCCu8; 16];
        let iv = [0xDDu8; 16];
        let plaintext = b"chacha20 test data 1234";

        let mut enc = VmessChunkCipher::new(SecurityType::Chacha20Poly1305, &key, &iv);
        let chunk = enc.encrypt_chunk(plaintext).unwrap();

        let mut dec = VmessChunkCipher::new(SecurityType::Chacha20Poly1305, &key, &iv);
        let decoded_len = dec.decode_length([chunk[0], chunk[1]]) as usize;
        let decrypted = dec.decrypt_chunk(&chunk[2..2 + decoded_len]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn vmess_chunk_cipher_none_passthrough() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let plaintext = b"none security passthrough";

        let mut enc = VmessChunkCipher::new(SecurityType::None, &key, &iv);
        let chunk = enc.encrypt_chunk(plaintext).unwrap();

        let mut dec = VmessChunkCipher::new(SecurityType::None, &key, &iv);
        let decoded_len = dec.decode_length([chunk[0], chunk[1]]) as usize;
        let decrypted = dec.decrypt_chunk(&chunk[2..2 + decoded_len]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn vmess_chunk_cipher_multiple_chunks() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let data1 = b"first chunk";
        let data2 = b"second chunk with more data";

        let mut enc = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let chunk1 = enc.encrypt_chunk(data1).unwrap();
        let chunk2 = enc.encrypt_chunk(data2).unwrap();

        let mut dec = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let len1 = dec.decode_length([chunk1[0], chunk1[1]]) as usize;
        let dec1 = dec.decrypt_chunk(&chunk1[2..2 + len1]).unwrap();
        assert_eq!(&dec1, data1);

        let len2 = dec.decode_length([chunk2[0], chunk2[1]]) as usize;
        let dec2 = dec.decrypt_chunk(&chunk2[2..2 + len2]).unwrap();
        assert_eq!(&dec2, data2);
    }

    #[test]
    fn vmess_derive_response_key_iv() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let (rk, ri) = derive_response_key_iv(&key, &iv);
        assert_ne!(rk, key);
        assert_ne!(ri, iv);
        let (rk2, ri2) = derive_response_key_iv(&key, &iv);
        assert_eq!(rk, rk2);
        assert_eq!(ri, ri2);
    }

    #[tokio::test]
    async fn vmess_aead_stream_round_trip() {
        let key = [0xAAu8; 16];
        let iv = [0xBBu8; 16];
        let (resp_key, resp_iv) = derive_response_key_iv(&key, &iv);

        let (client, server) = tokio::io::duplex(65536);
        let client_stream: ProxyStream = Box::new(client);
        let server_stream: ProxyStream = Box::new(server);

        let encoder = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let decoder = VmessChunkCipher::new(SecurityType::Aes128Gcm, &resp_key, &resp_iv);
        let mut writer_stream = VmessAeadStream::new(client_stream, encoder, decoder, SecurityType::Aes128Gcm);

        let server_enc = VmessChunkCipher::new(SecurityType::Aes128Gcm, &resp_key, &resp_iv);
        let server_dec = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let mut reader_stream = VmessAeadStream::new(server_stream, server_enc, server_dec, SecurityType::Aes128Gcm);

        let test_data = b"hello vmess aead stream!";
        writer_stream.write_all(test_data).await.unwrap();
        writer_stream.flush().await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        reader_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }
}
