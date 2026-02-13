use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, ProxyStream};
use crate::config::types::InboundConfig;
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

struct VlessClient {
    uuid: uuid::Uuid,
    #[allow(dead_code)]
    flow: Option<String>,
}

pub struct VlessInbound {
    tag: String,
    clients: Vec<VlessClient>,
    client_map: HashMap<[u8; 16], usize>,
}

impl VlessInbound {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let mut clients = Vec::new();

        if let Some(uuid_str) = config.settings.uuid.as_ref() {
            let uuid = uuid_str.parse::<uuid::Uuid>().map_err(|e| {
                anyhow::anyhow!("vless inbound '{}' invalid uuid: {}", config.tag, e)
            })?;
            clients.push(VlessClient {
                uuid,
                flow: config.settings.flow.clone(),
            });
        }

        if let Some(client_list) = config.settings.clients.as_ref() {
            for (idx, c) in client_list.iter().enumerate() {
                let uuid = c.uuid.parse::<uuid::Uuid>().map_err(|e| {
                    anyhow::anyhow!(
                        "vless inbound '{}' client #{} invalid uuid: {}",
                        config.tag,
                        idx,
                        e
                    )
                })?;
                clients.push(VlessClient {
                    uuid,
                    flow: c.flow.clone(),
                });
            }
        }

        if clients.is_empty() {
            anyhow::bail!(
                "vless inbound '{}' requires 'settings.uuid' or non-empty 'settings.clients'",
                config.tag
            );
        }

        let mut client_map = HashMap::new();
        for (idx, c) in clients.iter().enumerate() {
            client_map.insert(*c.uuid.as_bytes(), idx);
        }

        Ok(Self {
            tag: config.tag.clone(),
            clients,
            client_map,
        })
    }
}

#[async_trait]
impl InboundHandler for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, mut stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        // Read VLESS request header
        // [Version: 1B] [UUID: 16B] [AddonsLen: 1B] [Addons: N] [Cmd: 1B] [Port: 2B] [AddrType: 1B] [Addr: N]

        let version = stream.read_u8().await?;
        if version != 0x00 {
            anyhow::bail!("unsupported VLESS version: 0x{:02x}", version);
        }

        let mut uuid_bytes = [0u8; 16];
        stream.read_exact(&mut uuid_bytes).await?;

        let client_idx = self
            .client_map
            .get(&uuid_bytes)
            .ok_or_else(|| anyhow::anyhow!("vless inbound '{}' unknown client UUID", self.tag))?;
        let _client = &self.clients[*client_idx];

        // Read addons
        let addons_len = stream.read_u8().await? as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
        }

        let command = stream.read_u8().await?;
        let port = stream.read_u16().await?;

        // Read address
        let addr_type = stream.read_u8().await?;
        let target = match addr_type {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let addr = std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip));
                Address::Ip(std::net::SocketAddr::new(addr, port))
            }
            0x02 => {
                let domain_len = stream.read_u8().await? as usize;
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| anyhow::anyhow!("invalid domain name encoding"))?;
                Address::Domain(domain, port)
            }
            0x03 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let addr = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip));
                Address::Ip(std::net::SocketAddr::new(addr, port))
            }
            _ => anyhow::bail!("unknown VLESS address type: 0x{:02x}", addr_type),
        };

        // Send VLESS response header: [Version: 0x00] [AddonsLen: 0x00]
        stream.write_all(&[0x00, 0x00]).await?;

        let network = if command == 0x02 {
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
    use crate::config::types::{InboundSettings, SniffingConfig, VlessClientConfig};

    fn make_config(uuid: &str) -> InboundConfig {
        InboundConfig {
            tag: "vless-in".to_string(),
            protocol: "vless".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 443,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                uuid: Some(uuid.to_string()),
                ..Default::default()
            },
            max_connections: None,
        }
    }

    #[test]
    fn vless_inbound_creation() {
        let cfg = make_config("550e8400-e29b-41d4-a716-446655440000");
        let inbound = VlessInbound::new(&cfg).unwrap();
        assert_eq!(inbound.tag(), "vless-in");
        assert_eq!(inbound.clients.len(), 1);
    }

    #[test]
    fn vless_inbound_invalid_uuid_fails() {
        let cfg = make_config("not-a-uuid");
        assert!(VlessInbound::new(&cfg).is_err());
    }

    #[test]
    fn vless_inbound_requires_uuid_or_clients() {
        let cfg = InboundConfig {
            tag: "vless-in".to_string(),
            protocol: "vless".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 443,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        };
        assert!(VlessInbound::new(&cfg).is_err());
    }

    #[test]
    fn vless_inbound_multi_client() {
        let cfg = InboundConfig {
            tag: "vless-in".to_string(),
            protocol: "vless".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 443,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                clients: Some(vec![
                    VlessClientConfig {
                        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        flow: None,
                    },
                    VlessClientConfig {
                        uuid: "660e8400-e29b-41d4-a716-446655440001".to_string(),
                        flow: Some("xtls-rprx-vision".to_string()),
                    },
                ]),
                ..Default::default()
            },
            max_connections: None,
        };
        let inbound = VlessInbound::new(&cfg).unwrap();
        assert_eq!(inbound.clients.len(), 2);
    }

    #[tokio::test]
    async fn vless_inbound_handle_tcp_ipv4() {
        let cfg = make_config("550e8400-e29b-41d4-a716-446655440000");
        let inbound = VlessInbound::new(&cfg).unwrap();
        let uuid = "550e8400-e29b-41d4-a716-446655440000"
            .parse::<uuid::Uuid>()
            .unwrap();

        let (client, server) = tokio::io::duplex(4096);

        // Build VLESS request
        let mut req = Vec::new();
        req.push(0x00); // version
        req.extend_from_slice(uuid.as_bytes()); // UUID
        req.push(0x00); // addons len
        req.push(0x01); // cmd: TCP
        req.extend_from_slice(&443u16.to_be_bytes()); // port
        req.push(0x01); // addr type: IPv4
        req.extend_from_slice(&[1, 2, 3, 4]); // IP

        let mut client_stream: ProxyStream = Box::new(client);
        use tokio::io::AsyncWriteExt;
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = inbound.handle(server_stream, source).await.unwrap();

        assert_eq!(result.session.network, Network::Tcp);
        assert_eq!(
            result.session.target,
            Address::Ip("1.2.3.4:443".parse().unwrap())
        );
        assert!(result.udp_transport.is_none());
    }

    #[tokio::test]
    async fn vless_inbound_handle_unknown_uuid_fails() {
        let cfg = make_config("550e8400-e29b-41d4-a716-446655440000");
        let inbound = VlessInbound::new(&cfg).unwrap();
        let bad_uuid = [0xFFu8; 16];

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.push(0x00);
        req.extend_from_slice(&bad_uuid);
        req.push(0x00);
        req.push(0x01);
        req.extend_from_slice(&443u16.to_be_bytes());
        req.push(0x01);
        req.extend_from_slice(&[1, 2, 3, 4]);

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(inbound.handle(server_stream, source).await.is_err());
    }

    #[tokio::test]
    async fn vless_inbound_handle_domain() {
        let cfg = make_config("550e8400-e29b-41d4-a716-446655440000");
        let inbound = VlessInbound::new(&cfg).unwrap();
        let uuid = "550e8400-e29b-41d4-a716-446655440000"
            .parse::<uuid::Uuid>()
            .unwrap();

        let (client, server) = tokio::io::duplex(4096);

        let mut req = Vec::new();
        req.push(0x00);
        req.extend_from_slice(uuid.as_bytes());
        req.push(0x00); // addons len
        req.push(0x01); // cmd: TCP
        req.extend_from_slice(&443u16.to_be_bytes());
        req.push(0x02); // addr type: domain
        let domain = b"example.com";
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);

        let mut client_stream: ProxyStream = Box::new(client);
        client_stream.write_all(&req).await.unwrap();

        let server_stream: ProxyStream = Box::new(server);
        let source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = inbound.handle(server_stream, source).await.unwrap();

        assert_eq!(
            result.session.target,
            Address::Domain("example.com".to_string(), 443)
        );
    }
}
