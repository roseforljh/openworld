use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use crate::common::{Address, ProxyStream};
use crate::config::types::InboundConfig;
use crate::proxy::outbound::trojan::protocol::password_hash;
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

pub struct TrojanInbound {
    tag: String,
    password_hashes: HashSet<String>,
}

impl TrojanInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let mut password_hashes = HashSet::new();

        if let Some(password) = config.settings.password.as_ref() {
            password_hashes.insert(password_hash(password));
        }

        if password_hashes.is_empty() {
            anyhow::bail!(
                "trojan inbound '{}' requires 'settings.password'",
                config.tag
            );
        }

        Ok(Self {
            tag: config.tag.clone(),
            password_hashes,
        })
    }
}

#[async_trait]
impl InboundHandler for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, mut stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        // Read SHA224 hex hash (56 bytes)
        let mut hash_buf = [0u8; 56];
        stream.read_exact(&mut hash_buf).await?;
        let received_hash = String::from_utf8(hash_buf.to_vec())
            .map_err(|_| anyhow::anyhow!("trojan inbound: invalid password hash encoding"))?;

        if !self.password_hashes.contains(&received_hash) {
            anyhow::bail!("trojan inbound '{}' authentication failed", self.tag);
        }

        // Read CRLF
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            anyhow::bail!("trojan inbound: expected CRLF after password hash");
        }

        // Read command
        let command = stream.read_u8().await?;

        // Read address (ATYP + ADDR + PORT)
        let atyp = stream.read_u8().await?;
        let target = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let port = stream.read_u16().await?;
                Address::Ip(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                    port,
                ))
            }
            0x03 => {
                let domain_len = stream.read_u8().await? as usize;
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                let port = stream.read_u16().await?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| anyhow::anyhow!("trojan inbound: invalid domain encoding"))?;
                Address::Domain(domain, port)
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let port = stream.read_u16().await?;
                Address::Ip(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                    port,
                ))
            }
            _ => anyhow::bail!("trojan inbound: unsupported address type: 0x{:02x}", atyp),
        };

        // Read trailing CRLF
        stream.read_exact(&mut crlf).await?;

        let network = if command == 0x03 {
            Network::Udp
        } else {
            Network::Tcp
        };

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
            stream,
            udp_transport: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{InboundSettings, SniffingConfig};
    use tokio::io::AsyncWriteExt;

    fn make_config(password: &str) -> InboundConfig {
        InboundConfig {
            tag: "trojan-in".to_string(),
            protocol: "trojan".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 443,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                password: Some(password.to_string()),
                ..Default::default()
            },
            max_connections: None,
        }
    }

    #[test]
    fn trojan_inbound_creation() {
        let cfg = make_config("mypassword");
        let inbound = TrojanInbound::new(&cfg).unwrap();
        assert_eq!(inbound.tag(), "trojan-in");
        assert_eq!(inbound.password_hashes.len(), 1);
    }

    #[test]
    fn trojan_inbound_requires_password() {
        let cfg = InboundConfig {
            tag: "trojan-in".to_string(),
            protocol: "trojan".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 443,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        };
        assert!(TrojanInbound::new(&cfg).is_err());
    }

    #[tokio::test]
    async fn trojan_inbound_handle_tcp_ipv4() {
        let password = "testpassword";
        let cfg = make_config(password);
        let inbound = TrojanInbound::new(&cfg).unwrap();
        let hash = password_hash(password);

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.extend_from_slice(hash.as_bytes()); // 56 bytes SHA224 hex
        req.extend_from_slice(b"\r\n");
        req.push(0x01); // CMD_CONNECT
        req.push(0x01); // ATYP IPv4
        req.extend_from_slice(&[8, 8, 8, 8]); // IP
        req.extend_from_slice(&443u16.to_be_bytes()); // port
        req.extend_from_slice(b"\r\n");

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = inbound.handle(server_stream, source).await.unwrap();

        assert_eq!(result.session.network, Network::Tcp);
        assert_eq!(result.session.target, Address::Ip("8.8.8.8:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn trojan_inbound_wrong_password_fails() {
        let cfg = make_config("correct_password");
        let inbound = TrojanInbound::new(&cfg).unwrap();
        let wrong_hash = password_hash("wrong_password");

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.extend_from_slice(wrong_hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(0x01);
        req.push(0x01);
        req.extend_from_slice(&[1, 2, 3, 4]);
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(b"\r\n");

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(inbound.handle(server_stream, source).await.is_err());
    }

    #[tokio::test]
    async fn trojan_inbound_handle_domain() {
        let password = "domaintest";
        let cfg = make_config(password);
        let inbound = TrojanInbound::new(&cfg).unwrap();
        let hash = password_hash(password);

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.extend_from_slice(hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(0x01);
        req.push(0x03); // domain
        let domain = b"example.com";
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(b"\r\n");

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = inbound.handle(server_stream, source).await.unwrap();

        assert_eq!(result.session.target, Address::Domain("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn trojan_inbound_handle_udp() {
        let password = "udptest";
        let cfg = make_config(password);
        let inbound = TrojanInbound::new(&cfg).unwrap();
        let hash = password_hash(password);

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.extend_from_slice(hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(0x03); // CMD_UDP_ASSOCIATE
        req.push(0x01); // IPv4
        req.extend_from_slice(&[8, 8, 8, 8]);
        req.extend_from_slice(&53u16.to_be_bytes());
        req.extend_from_slice(b"\r\n");

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = inbound.handle(server_stream, source).await.unwrap();

        assert_eq!(result.session.network, Network::Udp);
    }
}
