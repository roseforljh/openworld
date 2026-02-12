use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

pub struct HttpOutbound {
    tag: String,
    server_addr: String,
    server_port: u16,
    username: Option<String>,
    password: Option<String>,
    dialer_config: Option<DialerConfig>,
}

impl HttpOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;
        let address = settings.address.as_ref().ok_or_else(|| {
            anyhow::anyhow!("http outbound '{}' missing 'address'", config.tag)
        })?;
        let port = settings.port.ok_or_else(|| {
            anyhow::anyhow!("http outbound '{}' missing 'port'", config.tag)
        })?;

        let username = settings.uuid.clone(); // reuse uuid field for username
        let password = settings.password.clone();

        debug!(
            tag = config.tag,
            server = %address,
            port = port,
            "http outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            server_addr: address.clone(),
            server_port: port,
            username,
            password,
            dialer_config: settings.dialer.clone(),
        })
    }
}

#[async_trait]
impl OutboundHandler for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let server = format!("{}:{}", self.server_addr, self.server_port);
        debug!(target = %session.target, server = %server, "http CONNECT proxy");

        let dialer = match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        };
        let mut stream = dialer.connect_host(&self.server_addr, self.server_port).await?;

        let target_str = match &session.target {
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Ip(addr) => addr.to_string(),
        };

        // Build CONNECT request
        let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target_str, target_str);

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            use base64::Engine;
            let cred = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user, pass));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
        }

        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        // Read response status line
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("http proxy: invalid response: {}", status_line.trim()))?;

        if status_code != 200 {
            anyhow::bail!("http proxy CONNECT failed: {}", status_line.trim());
        }

        // Skip remaining headers until empty line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        debug!(target = %session.target, "http CONNECT tunnel established");
        Ok(Box::new(reader.into_inner()))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("HTTP outbound does not support UDP")
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
    fn http_outbound_creation() {
        let config = OutboundConfig {
            tag: "http-out".to_string(),
            protocol: "http".to_string(),
            settings: OutboundSettings {
                address: Some("proxy.example.com".to_string()),
                port: Some(8080),
                ..Default::default()
            },
        };
        let outbound = HttpOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "http-out");
        assert_eq!(outbound.server_port, 8080);
    }

    #[test]
    fn http_outbound_missing_address_fails() {
        let config = OutboundConfig {
            tag: "http-out".to_string(),
            protocol: "http".to_string(),
            settings: OutboundSettings {
                port: Some(8080),
                ..Default::default()
            },
        };
        assert!(HttpOutbound::new(&config).is_err());
    }

    #[test]
    fn http_outbound_with_auth() {
        let config = OutboundConfig {
            tag: "http-auth".to_string(),
            protocol: "http".to_string(),
            settings: OutboundSettings {
                address: Some("proxy.example.com".to_string()),
                port: Some(8080),
                uuid: Some("user".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        };
        let outbound = HttpOutbound::new(&config).unwrap();
        assert!(outbound.username.is_some());
        assert!(outbound.password.is_some());
    }

    #[tokio::test]
    async fn http_outbound_connect_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = OutboundConfig {
            tag: "http-test".to_string(),
            protocol: "http".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(port),
                ..Default::default()
            },
        };
        let outbound = HttpOutbound::new(&config).unwrap();

        // Spawn mock HTTP proxy server
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            use tokio::io::AsyncReadExt;
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("CONNECT"));
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });

        let session = Session {
            target: Address::Domain("example.com".to_string(), 443),
            source: None,
            inbound_tag: String::new(),
            network: crate::proxy::Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };

        let stream = outbound.connect(&session).await.unwrap();
        drop(stream);
        handle.await.unwrap();
    }
}
