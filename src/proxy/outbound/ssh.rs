use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{BoxUdpTransport, Dialer, DialerConfig, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// SSH 隧道出站
///
/// 通过 SSH 连接建立 TCP 端口转发隧道 (类似 ssh -L)。
/// 简化实现：使用 SSH 协议握手后的直连通道。
///
/// 完整实现需要 SSH 密钥交换、认证等，这里提供框架和直连模式。
pub struct SshOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    username: String,
    auth_method: SshAuthMethod,
    dialer_config: Option<DialerConfig>,
}

#[derive(Debug, Clone)]
pub enum SshAuthMethod {
    Password(String),
    PrivateKey { key_path: String, passphrase: Option<String> },
    None,
}

/// SSH 协议版本交换的标识字符串
const SSH_CLIENT_VERSION: &str = "SSH-2.0-OpenWorld_0.1";

impl SshOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ssh: address required"))?;
        let port = settings.port.unwrap_or(22);
        let username = settings
            .username
            .as_deref()
            .unwrap_or("root")
            .to_string();
        let auth_method = if let Some(ref pw) = settings.password {
            SshAuthMethod::Password(pw.clone())
        } else if let Some(ref key) = settings.private_key {
            SshAuthMethod::PrivateKey {
                key_path: key.clone(),
                passphrase: settings.private_key_passphrase.clone(),
            }
        } else {
            SshAuthMethod::None
        };

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            username,
            auth_method,
            dialer_config: settings.dialer.clone(),
        })
    }

    pub fn tag_str(&self) -> &str {
        &self.tag
    }

    pub fn server(&self) -> (&str, u16) {
        (&self.server_addr, self.server_port)
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn auth_method(&self) -> &SshAuthMethod {
        &self.auth_method
    }
}

#[async_trait]
impl OutboundHandler for SshOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        debug!(
            tag = self.tag,
            dest = %session.target,
            server = %self.server_addr,
            port = self.server_port,
            "SSH tunnel connecting"
        );

        // 连接到 SSH 服务器
        let dialer = match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        };
        let mut stream = dialer.connect_host(&self.server_addr, self.server_port).await?;

        // SSH 版本交换
        let client_version = format!("{}\r\n", SSH_CLIENT_VERSION);
        stream.write_all(client_version.as_bytes()).await?;
        stream.flush().await?;

        // 读取服务器版本
        let mut server_version_buf = vec![0u8; 256];
        let n = stream.read(&mut server_version_buf).await?;
        let server_version = String::from_utf8_lossy(&server_version_buf[..n]);
        debug!(
            server_version = %server_version.trim(),
            "SSH server version received"
        );

        if !server_version.starts_with("SSH-2.0") {
            anyhow::bail!("unsupported SSH version: {}", server_version.trim());
        }

        // 注意：完整的 SSH 实现需要密钥交换、认证、通道建立等
        // 这里返回底层 TCP 流作为隧道
        // 实际使用时应集成 russh 或类似库
        debug!(
            tag = self.tag,
            dest = %session.target,
            "SSH connection established (simplified tunnel)"
        );

        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("SSH does not support UDP")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn ssh_outbound_creation() {
        let config = OutboundConfig {
            tag: "ssh-test".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings {
                address: Some("example.com".to_string()),
                port: Some(22),
                username: Some("admin".to_string()),
                password: Some("secret".to_string()),
                ..Default::default()
            },
        };
        let outbound = SshOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "ssh-test");
        assert_eq!(outbound.server(), ("example.com", 22));
        assert_eq!(outbound.username(), "admin");
        match outbound.auth_method() {
            SshAuthMethod::Password(pw) => assert_eq!(pw, "secret"),
            _ => panic!("expected password auth"),
        }
    }

    #[test]
    fn ssh_outbound_default_port() {
        let config = OutboundConfig {
            tag: "ssh-test".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings {
                address: Some("example.com".to_string()),
                ..Default::default()
            },
        };
        let outbound = SshOutbound::new(&config).unwrap();
        assert_eq!(outbound.server().1, 22);
        assert_eq!(outbound.username(), "root");
    }

    #[test]
    fn ssh_outbound_missing_address() {
        let config = OutboundConfig {
            tag: "ssh-test".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings::default(),
        };
        assert!(SshOutbound::new(&config).is_err());
    }

    #[test]
    fn ssh_auth_method_none() {
        let config = OutboundConfig {
            tag: "ssh-test".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings {
                address: Some("host.com".to_string()),
                ..Default::default()
            },
        };
        let outbound = SshOutbound::new(&config).unwrap();
        match outbound.auth_method() {
            SshAuthMethod::None => {}
            _ => panic!("expected none auth"),
        }
    }

    #[test]
    fn ssh_client_version_string() {
        assert!(SSH_CLIENT_VERSION.starts_with("SSH-2.0"));
    }
}
