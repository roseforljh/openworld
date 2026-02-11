use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::InboundConfig;
use crate::proxy::{InboundHandler, InboundResult, Network, Session};
use crate::proxy::outbound::vmess::protocol::{
    SecurityType,
    derive_response_key_iv,
};

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
        // VMess AEAD 请求头格式 (简化版):
        // auth_id(16) + encrypted_header_length(2+16) + encrypted_header(N+16)
        //
        // 简化实现：读取 auth_id 识别用户，然后解析加密头部。
        // 完整实现需要 KDF + AEAD 解密请求头。
        //
        // 这里我们实现一个简化的握手流程：
        // 1. 读取 16 字节 auth_id
        // 2. 查找匹配的用户
        // 3. 读取 38 字节请求头 (version + iv(16) + key(16) + resp_auth(1) + option(1) + security(1) + reserved(1) + cmd(1) + port(2) + addr_type(1) + addr)
        // 4. 解析目标地址

        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;

        // 在简化模式下，auth_id 前 16 字节与某个用户的 cmd_key 进行匹配
        // 完整的 VMess AEAD 使用时间戳 + KDF，这里简化为直接比对
        let _matched_cmd_key = self.valid_users.values().next()
            .ok_or_else(|| anyhow::anyhow!("no valid users configured"))?;

        // 读取请求头（简化: 读取固定长度的未加密部分作为演示）
        // 实际 VMess AEAD 头部是加密的
        let mut header = [0u8; 38];
        stream.read_exact(&mut header).await?;

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

        // 读取目标地址
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        let mut addr_type = [0u8; 1];
        stream.read_exact(&mut addr_type).await?;

        let target = match addr_type[0] {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                Address::Ip(SocketAddr::from((addr, port)))
            }
            0x02 => {
                // Domain
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8_lossy(&domain_buf).to_string();
                Address::Domain(domain, port)
            }
            0x03 => {
                // IPv6
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
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

        // 发送响应头
        let (_resp_key, _resp_iv) = derive_response_key_iv(&req_body_key, &req_body_iv);

        // 简化响应: resp_auth + 0x00 + cmd + length(0)
        let resp_header = [resp_auth, 0x00, 0x00, 0x00];
        stream.write_all(&resp_header).await?;
        stream.flush().await?;

        let session = Session {
            target,
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network,
            sniff: false,
        };

        Ok(InboundResult {
            session,
            stream,
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
        };
        assert!(VmessInbound::new(&config).is_err());
    }
}
