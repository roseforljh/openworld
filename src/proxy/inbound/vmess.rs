use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::InboundConfig;
use crate::proxy::outbound::vmess::protocol::{derive_response_key_iv, SecurityType};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

/// VMess 入站（服务端）
///
/// 解析 VMess 客户端请求头，验证 UUID，建立 AEAD 加密隧道。
pub struct VmessInbound {
    tag: String,
    /// UUID -> cmd_key 的映射
    valid_users: HashMap<[u8; 16], [u8; 16]>,
}

impl VmessInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let mut valid_users = HashMap::new();

        // 从 clients 配置加载
        if let Some(ref clients) = config.settings.clients {
            for client in clients {
                let uuid = client.uuid.parse::<uuid::Uuid>()?;
                let uuid_bytes = *uuid.as_bytes();
                let cmd_key = crate::proxy::outbound::vmess::protocol::uuid_to_cmd_key(&uuid_bytes);
                valid_users.insert(uuid_bytes, cmd_key);
            }
        }

        // 从顶层 uuid 配置加载
        if let Some(ref uuid_str) = config.settings.uuid {
            let uuid = uuid_str.parse::<uuid::Uuid>()?;
            let uuid_bytes = *uuid.as_bytes();
            let cmd_key = crate::proxy::outbound::vmess::protocol::uuid_to_cmd_key(&uuid_bytes);
            valid_users.insert(uuid_bytes, cmd_key);
        }

        if valid_users.is_empty() {
            anyhow::bail!("vmess inbound requires at least one uuid or client");
        }

        Ok(Self {
            tag: config.tag.clone(),
            valid_users,
        })
    }

    pub fn user_count(&self) -> usize {
        self.valid_users.len()
    }
}

#[async_trait]
impl InboundHandler for VmessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, mut stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        use crate::proxy::outbound::vmess::protocol::{
            create_auth_id, fnv1a_hash, kdf, VmessChunkCipher,
        };
        use crate::proxy::outbound::vmess::VmessAeadStream;
        use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};

        // ── Step 1: Read auth_id (16 bytes) ──
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;

        // Match auth_id against valid users using a ±120s timestamp window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut matched_cmd_key: Option<[u8; 16]> = None;
        'outer: for cmd_key in self.valid_users.values() {
            for delta in -120i64..=120 {
                let ts = (now as i64 + delta) as u64;
                let expected = create_auth_id(cmd_key, ts);
                if expected == auth_id {
                    matched_cmd_key = Some(*cmd_key);
                    break 'outer;
                }
            }
        }

        let cmd_key = matched_cmd_key
            .ok_or_else(|| anyhow::anyhow!("vmess inbound: no matching user for auth_id"))?;

        // ── Step 2: Read encrypted_length (18 bytes) + nonce (8 bytes) ──
        let mut encrypted_length = [0u8; 18]; // 2 + 16 tag
        stream.read_exact(&mut encrypted_length).await?;

        let mut conn_nonce = [0u8; 8];
        stream.read_exact(&mut conn_nonce).await?;

        // Decrypt header length
        let length_key_material = kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Key Length",
                &auth_id[..],
                &conn_nonce[..],
            ],
        );
        let length_key: [u8; 16] = length_key_material[..16].try_into().unwrap();
        let length_nonce_material = kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Nonce Length",
                &auth_id[..],
                &conn_nonce[..],
            ],
        );
        let length_nonce: [u8; 12] = length_nonce_material[..12].try_into().unwrap();

        let length_cipher = Aes128Gcm::new_from_slice(&length_key)
            .map_err(|e| anyhow::anyhow!("length key init: {}", e))?;
        let decrypted_length = length_cipher
            .decrypt(Nonce::from_slice(&length_nonce), encrypted_length.as_ref())
            .map_err(|e| anyhow::anyhow!("length decrypt: {}", e))?;

        let header_len = u16::from_be_bytes([decrypted_length[0], decrypted_length[1]]) as usize;

        // ── Step 3: Read encrypted header ──
        let mut encrypted_header = vec![0u8; header_len];
        stream.read_exact(&mut encrypted_header).await?;

        // Decrypt header
        let header_key_material = kdf(
            &cmd_key,
            &[b"VMess Header AEAD Key", &auth_id[..], &conn_nonce[..]],
        );
        let header_key: [u8; 16] = header_key_material[..16].try_into().unwrap();
        let header_nonce_material = kdf(
            &cmd_key,
            &[b"VMess Header AEAD Nonce", &auth_id[..], &conn_nonce[..]],
        );
        let header_nonce: [u8; 12] = header_nonce_material[..12].try_into().unwrap();

        let header_cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| anyhow::anyhow!("header key init: {}", e))?;
        let header = header_cipher
            .decrypt(Nonce::from_slice(&header_nonce), encrypted_header.as_ref())
            .map_err(|e| anyhow::anyhow!("header decrypt: {}", e))?;

        // ── Step 4: Parse header ──
        // header: version(1) + body_iv(16) + body_key(16) + resp_auth(1) + option(1) +
        //         P_sec(1) + reserved(1) + cmd(1) + port(2) + addr_type(1) + addr... + FNV1a(4)
        if header.len() < 42 {
            anyhow::bail!("vmess inbound: header too short: {} bytes", header.len());
        }

        // Verify FNV1a checksum (last 4 bytes)
        let checksum_offset = header.len() - 4;
        let expected_checksum = u32::from_be_bytes([
            header[checksum_offset],
            header[checksum_offset + 1],
            header[checksum_offset + 2],
            header[checksum_offset + 3],
        ]);
        let actual_checksum = fnv1a_hash(&header[..checksum_offset]);
        if expected_checksum != actual_checksum {
            anyhow::bail!(
                "vmess inbound: FNV1a checksum mismatch: expected 0x{:08x}, got 0x{:08x}",
                expected_checksum,
                actual_checksum
            );
        }

        let _version = header[0];
        let req_body_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let req_body_key: [u8; 16] = header[17..33].try_into().unwrap();
        let resp_auth = header[33];
        let _option = header[34];
        let security_byte = header[35] & 0x0F;
        let cmd = header[37];

        let security = match security_byte {
            0x03 => SecurityType::Aes128Gcm,
            0x04 => SecurityType::Chacha20Poly1305,
            0x05 => SecurityType::None,
            _ => SecurityType::Aes128Gcm,
        };

        // Parse target address from header[38..checksum_offset]
        let addr_data = &header[38..checksum_offset];
        let port = u16::from_be_bytes([addr_data[0], addr_data[1]]);
        let addr_type = addr_data[2];

        let target = match addr_type {
            0x01 => {
                // IPv4
                let addr: [u8; 4] = addr_data[3..7].try_into().unwrap();
                Address::Ip(SocketAddr::from((addr, port)))
            }
            0x02 => {
                // Domain
                let domain_len = addr_data[3] as usize;
                let domain = String::from_utf8_lossy(&addr_data[4..4 + domain_len]).to_string();
                Address::Domain(domain, port)
            }
            0x03 => {
                // IPv6
                let addr: [u8; 16] = addr_data[3..19].try_into().unwrap();
                Address::Ip(SocketAddr::from((addr, port)))
            }
            other => {
                anyhow::bail!("vmess inbound: unknown address type: {}", other);
            }
        };

        let network = if cmd == 0x01 {
            Network::Tcp
        } else {
            Network::Udp
        };

        debug!(
            tag = self.tag,
            source = %source,
            dest = %target,
            security = ?security,
            "VMess inbound connection"
        );

        // ── Step 5: Send AEAD encrypted response header ──
        let (resp_key, resp_iv) = derive_response_key_iv(&req_body_key, &req_body_iv);

        let resp_header_key = kdf(&resp_key, &[b"AEAD Resp Header Key"]);
        let resp_header_nonce = kdf(&resp_iv, &[b"AEAD Resp Header IV"]);
        let rk: [u8; 16] = resp_header_key[..16].try_into().unwrap();
        let rn: [u8; 12] = resp_header_nonce[..12].try_into().unwrap();

        let resp_cipher = Aes128Gcm::new_from_slice(&rk)
            .map_err(|e| anyhow::anyhow!("resp header key init: {}", e))?;
        let resp_plaintext = [resp_auth, 0x00, 0x00, 0x00];
        let resp_encrypted = resp_cipher
            .encrypt(Nonce::from_slice(&rn), resp_plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("resp header encrypt: {}", e))?;
        stream.write_all(&resp_encrypted).await?;
        stream.flush().await?;

        // ── Step 6: Wrap stream with VmessAeadStream ──
        // Server encoder: encrypts data to client using resp_key/resp_iv
        let encoder = VmessChunkCipher::new(security, &resp_key, &resp_iv);
        // Server decoder: decrypts data from client using req_body_key/req_body_iv
        let decoder = VmessChunkCipher::new(security, &req_body_key, &req_body_iv);

        let vmess_stream: ProxyStream =
            Box::new(VmessAeadStream::new(stream, encoder, decoder, security));

        let session = Session {
            target,
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network,
            sniff: false,
            detected_protocol: None,
        };

        Ok(InboundResult {
            session,
            stream: vmess_stream,
            udp_transport: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{InboundSettings, VlessClientConfig};

    #[test]
    fn vmess_inbound_creation() {
        let config = InboundConfig {
            tag: "vmess-in".to_string(),
            protocol: "vmess".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 10086,
            sniffing: Default::default(),
            settings: InboundSettings {
                uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                ..Default::default()
            },
            max_connections: None,
        };
        let inbound = VmessInbound::new(&config).unwrap();
        assert_eq!(inbound.tag(), "vmess-in");
        assert_eq!(inbound.user_count(), 1);
    }

    #[test]
    fn vmess_inbound_multi_user() {
        let config = InboundConfig {
            tag: "vmess-in".to_string(),
            protocol: "vmess".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 10086,
            sniffing: Default::default(),
            settings: InboundSettings {
                clients: Some(vec![
                    VlessClientConfig {
                        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        flow: None,
                    },
                    VlessClientConfig {
                        uuid: "660e8400-e29b-41d4-a716-446655440000".to_string(),
                        flow: None,
                    },
                ]),
                ..Default::default()
            },
            max_connections: None,
        };
        let inbound = VmessInbound::new(&config).unwrap();
        assert_eq!(inbound.user_count(), 2);
    }

    #[test]
    fn vmess_inbound_requires_uuid() {
        let config = InboundConfig {
            tag: "vmess-in".to_string(),
            protocol: "vmess".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 10086,
            sniffing: Default::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        };
        assert!(VmessInbound::new(&config).is_err());
    }

    #[test]
    fn vmess_inbound_invalid_uuid() {
        let config = InboundConfig {
            tag: "vmess-in".to_string(),
            protocol: "vmess".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 10086,
            sniffing: Default::default(),
            settings: InboundSettings {
                uuid: Some("not-a-valid-uuid".to_string()),
                ..Default::default()
            },
            max_connections: None,
        };
        assert!(VmessInbound::new(&config).is_err());
    }
}
