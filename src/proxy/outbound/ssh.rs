use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// SSH 隧道出站
///
/// 通过 SSH 连接建立 TCP 端口转发隧道 (类似 ssh -L / direct-tcpip)。
/// 需要 feature = "ssh" 启用 russh 依赖。
///
/// 每次 `connect()` 调用创建独立的 SSH 连接和 direct-tcpip 通道。
pub struct SshOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    username: String,
    auth_method: SshAuthMethod,
}

#[derive(Debug, Clone)]
pub enum SshAuthMethod {
    Password(String),
    PrivateKey { key_data: String, passphrase: Option<String> },
    None,
}

#[cfg(feature = "ssh")]
struct SshHandler;

#[cfg(feature = "ssh")]
#[async_trait]
impl russh::client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Accept all host keys (like StrictHostKeyChecking=no)
        // TODO: implement known_hosts verification
        Ok(true)
    }
}

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
                key_data: key.clone(),
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
        #[cfg(feature = "ssh")]
        {
            // === 1. 建立 SSH 连接 ===
            let ssh_config = russh::client::Config {
                ..Default::default()
            };

            let addr = format!("{}:{}", self.server_addr, self.server_port);
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr)
                .await?
                .collect();
            if addrs.is_empty() {
                anyhow::bail!("ssh: failed to resolve {}", addr);
            }

            debug!(
                server = %self.server_addr,
                port = self.server_port,
                "SSH connecting"
            );

            let mut handle = russh::client::connect(
                std::sync::Arc::new(ssh_config),
                addrs[0],
                SshHandler {},
            )
            .await?;

            // === 2. 认证 ===
            match &self.auth_method {
                SshAuthMethod::Password(password) => {
                    let auth_ok = handle
                        .authenticate_password(&self.username, password)
                        .await?;
                    if !auth_ok {
                        anyhow::bail!("ssh: password authentication failed for user '{}'", self.username);
                    }
                }
                SshAuthMethod::PrivateKey { key_data, passphrase } => {
                    let key = if let Some(pass) = passphrase {
                        russh_keys::decode_secret_key(key_data, Some(pass))?
                    } else {
                        russh_keys::decode_secret_key(key_data, None)?
                    };
                    let auth_ok = handle
                        .authenticate_publickey(&self.username, std::sync::Arc::new(key))
                        .await?;
                    if !auth_ok {
                        anyhow::bail!("ssh: public key authentication failed for user '{}'", self.username);
                    }
                }
                SshAuthMethod::None => {
                    let auth_ok = handle
                        .authenticate_none(&self.username)
                        .await?;
                    if !auth_ok {
                        anyhow::bail!("ssh: none authentication failed for user '{}'", self.username);
                    }
                }
            }

            debug!(
                server = %self.server_addr,
                user = %self.username,
                "SSH authenticated"
            );

            // === 3. 打开 direct-tcpip 通道 ===
            let (host, port) = match &session.target {
                crate::common::Address::Ip(addr) => (addr.ip().to_string(), addr.port()),
                crate::common::Address::Domain(domain, port) => (domain.clone(), *port),
            };

            debug!(
                tag = self.tag,
                dest_host = %host,
                dest_port = port,
                "SSH direct-tcpip channel opening"
            );

            let channel = handle
                .channel_open_direct_tcpip(
                    &host,
                    port.into(),
                    "127.0.0.1",
                    0,
                )
                .await?;

            debug!(
                tag = self.tag,
                dest = %session.target,
                "SSH channel established"
            );

            // === 4. 使用 Channel::into_stream() 直接转为 AsyncRead + AsyncWrite ===
            let stream = channel.into_stream();

            // 将 handle 移入后台保活（Handle 实现了 Future，连接断开时完成）
            tokio::spawn(async move {
                let _ = handle.await;
                debug!("SSH connection handle closed");
            });

            Ok(Box::new(stream))
        }

        #[cfg(not(feature = "ssh"))]
        {
            let _ = session;
            anyhow::bail!("SSH support requires the 'ssh' feature to be enabled")
        }
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
    fn ssh_auth_method_private_key() {
        let config = OutboundConfig {
            tag: "ssh-test".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings {
                address: Some("host.com".to_string()),
                private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
                private_key_passphrase: Some("mypass".to_string()),
                ..Default::default()
            },
        };
        let outbound = SshOutbound::new(&config).unwrap();
        match outbound.auth_method() {
            SshAuthMethod::PrivateKey { key_data, passphrase } => {
                assert!(key_data.contains("OPENSSH"));
                assert_eq!(passphrase.as_deref(), Some("mypass"));
            }
            _ => panic!("expected private key auth"),
        }
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
}
