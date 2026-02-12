pub mod noise;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

use noise::{
    WireGuardKeys,
    create_handshake_init, parse_base64_key,
};

pub struct WireGuardPeer {
    pub public_key: PublicKey,
    pub preshared_key: [u8; 32],
    pub endpoint: String,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub keepalive: Option<u16>,
}

pub struct WireGuardOutbound {
    tag: String,
    private_key: StaticSecret,
    public_key: PublicKey,
    peers: Vec<WireGuardPeer>,
    #[allow(dead_code)]
    local_address: Option<String>,
    mtu: u16,
}

impl WireGuardOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let settings = &config.settings;

        let private_key_str = settings.private_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("wireguard '{}' missing 'private_key'", config.tag)
        })?;
        let private_key_bytes = parse_base64_key(private_key_str)?;
        let private_key = StaticSecret::from(private_key_bytes);
        let public_key = PublicKey::from(&private_key);

        let mut peers = Vec::new();

        // 新格式：多 Peer 配置
        if let Some(peer_configs) = &settings.peers {
            for pc in peer_configs {
                let peer_pub_bytes = parse_base64_key(&pc.public_key)?;
                let peer_pub_key = PublicKey::from(peer_pub_bytes);

                let preshared_key = if let Some(psk) = &pc.preshared_key {
                    parse_base64_key(psk)?
                } else {
                    [0u8; 32]
                };

                let endpoint = pc.endpoint.clone().unwrap_or_else(|| {
                    format!(
                        "{}:{}",
                        settings.address.as_deref().unwrap_or("127.0.0.1"),
                        settings.port.unwrap_or(51820)
                    )
                });

                let allowed_ips: Vec<ipnet::IpNet> = pc.allowed_ips
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();

                peers.push(WireGuardPeer {
                    public_key: peer_pub_key,
                    preshared_key,
                    endpoint,
                    allowed_ips,
                    keepalive: pc.keepalive,
                });
            }
        }

        // 回退：旧格式单 Peer
        if peers.is_empty() {
            let peer_public_str = settings.peer_public_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("wireguard '{}' missing 'peer_public_key'", config.tag)
            })?;
            let peer_public_bytes = parse_base64_key(peer_public_str)?;
            let peer_public_key = PublicKey::from(peer_public_bytes);

            let preshared_key = if let Some(psk) = settings.preshared_key.as_ref() {
                parse_base64_key(psk)?
            } else {
                [0u8; 32]
            };

            let endpoint = format!(
                "{}:{}",
                settings.address.as_deref().unwrap_or("127.0.0.1"),
                settings.port.unwrap_or(51820)
            );

            peers.push(WireGuardPeer {
                public_key: peer_public_key,
                preshared_key,
                endpoint,
                allowed_ips: vec![
                    "0.0.0.0/0".parse().unwrap(),
                    "::/0".parse().unwrap(),
                ],
                keepalive: settings.keepalive,
            });
        }

        let local_address = settings.local_address.clone();
        let mtu = settings.mtu.unwrap_or(1420);

        debug!(
            tag = config.tag,
            peer_count = peers.len(),
            mtu = mtu,
            "wireguard outbound created"
        );

        Ok(Self {
            tag: config.tag.clone(),
            private_key,
            public_key,
            peers,
            local_address,
            mtu,
        })
    }

    /// 根据目标地址选择匹配的 Peer（按 allowed_ips 最长前缀匹配）
    #[allow(dead_code)]
    fn select_peer(&self, target: &std::net::IpAddr) -> Option<&WireGuardPeer> {
        let mut best: Option<(&WireGuardPeer, u8)> = None;
        for peer in &self.peers {
            for net in &peer.allowed_ips {
                if net.contains(target) {
                    let prefix = net.prefix_len();
                    if best.is_none() || prefix > best.unwrap().1 {
                        best = Some((peer, prefix));
                    }
                }
            }
        }
        best.map(|(p, _)| p).or_else(|| self.peers.first())
    }
}

#[async_trait]
impl OutboundHandler for WireGuardOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _session: &Session) -> Result<ProxyStream> {
        let peer = self.peers.first()
            .ok_or_else(|| anyhow::anyhow!("wireguard: no peers configured"))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let endpoint: SocketAddr = tokio::net::lookup_host(&peer.endpoint)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve endpoint: {}", peer.endpoint))?;
        socket.connect(endpoint).await?;

        let keys = WireGuardKeys {
            private_key: self.private_key.clone(),
            public_key: self.public_key,
            peer_public_key: peer.public_key,
            preshared_key: peer.preshared_key,
        };

        let sender_index: u32 = rand::random();
        let (init_msg, ck, h) = create_handshake_init(&keys, sender_index)?;

        socket.send(&init_msg).await?;
        debug!(tag = self.tag, endpoint = %endpoint, "wireguard handshake init sent");

        let mut resp_buf = [0u8; 256];
        let resp_timeout = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv(&mut resp_buf),
        ).await
        .map_err(|_| anyhow::anyhow!("wireguard handshake timeout"))?;

        let n = resp_timeout?;
        let transport_keys = noise::parse_handshake_resp(
            &resp_buf[..n],
            &keys,
            sender_index,
            ck,
            h,
        )?;

        debug!(tag = self.tag, "wireguard handshake complete");

        let (client, server) = tokio::io::duplex(self.mtu as usize * 4);
        let socket = Arc::new(socket);
        let transport_keys = Arc::new(Mutex::new(transport_keys));
        let mtu = self.mtu as usize;

        let socket_send = socket.clone();
        let keys_send = transport_keys.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu];
            let mut reader = server;
            loop {
                use tokio::io::AsyncReadExt;
                let n = match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut keys = keys_send.lock().await;
                match noise::encrypt_transport(&mut keys, &buf[..n]) {
                    Ok(msg) => {
                        if socket_send.send(&msg).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let socket_recv = socket;
        let keys_recv = transport_keys;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            let (_, mut writer) = tokio::io::split(client);
            loop {
                use tokio::io::AsyncWriteExt;
                let n = match socket_recv.recv(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut keys = keys_recv.lock().await;
                match noise::decrypt_transport(&mut keys, &buf[..n]) {
                    Ok(plain) => {
                        if writer.write_all(&plain).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        anyhow::bail!("wireguard TCP tunneling requires IP-level routing (TUN integration)")
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("wireguard UDP not yet supported (requires TUN integration)")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    fn make_test_keypair() -> (String, String) {
        let (secret, public) = noise::generate_keypair();
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD;
        let priv_b64 = enc.encode(secret.as_bytes());
        let pub_b64 = enc.encode(public.as_bytes());
        (priv_b64, pub_b64)
    }

    #[test]
    fn wireguard_outbound_creation() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer_pub) = make_test_keypair();

        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                private_key: Some(priv_key),
                peer_public_key: Some(peer_pub),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "wg-test");
        assert_eq!(outbound.peers.len(), 1);
        assert_eq!(outbound.mtu, 1420);
    }

    #[test]
    fn wireguard_outbound_missing_private_key_fails() {
        let (_, peer_pub) = make_test_keypair();
        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                peer_public_key: Some(peer_pub),
                ..Default::default()
            },
        };
        assert!(WireGuardOutbound::new(&config).is_err());
    }

    #[test]
    fn wireguard_outbound_missing_peer_key_fails() {
        let (priv_key, _) = make_test_keypair();
        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                private_key: Some(priv_key),
                ..Default::default()
            },
        };
        assert!(WireGuardOutbound::new(&config).is_err());
    }

    #[test]
    fn wireguard_outbound_with_preshared_key() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer_pub) = make_test_keypair();
        use base64::Engine;
        let psk = base64::engine::general_purpose::STANDARD.encode([0xABu8; 32]);

        let config = OutboundConfig {
            tag: "wg-psk".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                private_key: Some(priv_key),
                peer_public_key: Some(peer_pub),
                preshared_key: Some(psk),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();
        assert_ne!(outbound.peers[0].preshared_key, [0u8; 32]);
    }

    #[test]
    fn wireguard_outbound_custom_mtu() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer_pub) = make_test_keypair();

        let config = OutboundConfig {
            tag: "wg-mtu".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                private_key: Some(priv_key),
                peer_public_key: Some(peer_pub),
                mtu: Some(1280),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();
        assert_eq!(outbound.mtu, 1280);
    }

    #[test]
    fn wireguard_multi_peer_config() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer1_pub) = make_test_keypair();
        let (_, peer2_pub) = make_test_keypair();

        let config = OutboundConfig {
            tag: "wg-multi".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                private_key: Some(priv_key),
                peers: Some(vec![
                    crate::config::types::WireGuardPeerConfig {
                        public_key: peer1_pub,
                        endpoint: Some("10.0.0.1:51820".to_string()),
                        allowed_ips: vec!["10.0.0.0/24".to_string()],
                        keepalive: Some(25),
                        preshared_key: None,
                    },
                    crate::config::types::WireGuardPeerConfig {
                        public_key: peer2_pub,
                        endpoint: Some("10.0.1.1:51820".to_string()),
                        allowed_ips: vec!["10.0.1.0/24".to_string()],
                        keepalive: Some(30),
                        preshared_key: None,
                    },
                ]),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();
        assert_eq!(outbound.peers.len(), 2);
        assert_eq!(outbound.peers[0].keepalive, Some(25));
        assert_eq!(outbound.peers[1].keepalive, Some(30));
    }

    #[test]
    fn wireguard_peer_selection_by_allowed_ips() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer1_pub) = make_test_keypair();
        let (_, peer2_pub) = make_test_keypair();

        let config = OutboundConfig {
            tag: "wg-select".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                private_key: Some(priv_key),
                peers: Some(vec![
                    crate::config::types::WireGuardPeerConfig {
                        public_key: peer1_pub.clone(),
                        endpoint: Some("10.0.0.1:51820".to_string()),
                        allowed_ips: vec!["10.0.0.0/24".to_string()],
                        keepalive: None,
                        preshared_key: None,
                    },
                    crate::config::types::WireGuardPeerConfig {
                        public_key: peer2_pub.clone(),
                        endpoint: Some("10.0.1.1:51820".to_string()),
                        allowed_ips: vec!["10.0.1.0/24".to_string()],
                        keepalive: None,
                        preshared_key: None,
                    },
                ]),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();

        // 10.0.0.5 应匹配 peer1 (10.0.0.0/24)
        let target: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let peer = outbound.select_peer(&target).unwrap();
        assert_eq!(peer.endpoint, "10.0.0.1:51820");

        // 10.0.1.5 应匹配 peer2 (10.0.1.0/24)
        let target: std::net::IpAddr = "10.0.1.5".parse().unwrap();
        let peer = outbound.select_peer(&target).unwrap();
        assert_eq!(peer.endpoint, "10.0.1.1:51820");
    }

    #[test]
    fn wireguard_keepalive_config() {
        let (priv_key, _) = make_test_keypair();
        let (_, peer_pub) = make_test_keypair();

        let config = OutboundConfig {
            tag: "wg-ka".to_string(),
            protocol: "wireguard".to_string(),
            settings: OutboundSettings {
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                private_key: Some(priv_key),
                peer_public_key: Some(peer_pub),
                keepalive: Some(25),
                ..Default::default()
            },
        };

        let outbound = WireGuardOutbound::new(&config).unwrap();
        assert_eq!(outbound.peers[0].keepalive, Some(25));
    }
}
