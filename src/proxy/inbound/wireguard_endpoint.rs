//! WireGuard Endpoint 入站：作为 WireGuard 服务端接收客户端隧道连接
//!
//! 接收 WireGuard 握手 → 解密隧道 IP 包 → 提取目标地址 → 转发到出站

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::types::InboundConfig;
use crate::proxy::outbound::wireguard::noise::{
    self, TransportKeys, WireGuardKeys, parse_base64_key, parse_handshake_init,
    create_handshake_resp, decrypt_transport,
};

/// WireGuard 客户端会话
struct WgSession {
    transport_keys: TransportKeys,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    peer_public_key: PublicKey,
}

/// WireGuard Endpoint 配置
pub struct WireGuardEndpoint {
    tag: String,
    private_key: StaticSecret,
    public_key: PublicKey,
    allowed_peers: Vec<PublicKey>,
    preshared_key: [u8; 32],
    listen_port: u16,
    sessions: Arc<RwLock<HashMap<u32, WgSession>>>,
    next_index: Arc<Mutex<u32>>,
}

impl WireGuardEndpoint {
    pub fn new(config: &InboundConfig) -> Result<Self> {
        let settings = &config.settings;

        let private_key_str = settings
            .private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("wireguard endpoint missing private_key"))?;

        let pk_bytes = parse_base64_key(private_key_str)?;
        let private_key = StaticSecret::from(pk_bytes);
        let public_key = PublicKey::from(&private_key);

        let mut allowed_peers = Vec::new();
        if let Some(peers) = &settings.wg_peers {
            for peer in peers {
                let pk = parse_base64_key(&peer.public_key)?;
                allowed_peers.push(PublicKey::from(pk));
            }
        }

        if allowed_peers.is_empty() {
            anyhow::bail!("wireguard endpoint requires at least one peer");
        }

        let preshared_key = if let Some(psk_str) = &settings.preshared_key {
            parse_base64_key(psk_str)?
        } else {
            [0u8; 32]
        };

        let listen_port = config.port;

        info!(
            tag = config.tag.as_str(),
            port = listen_port,
            peers = allowed_peers.len(),
            "WireGuard Endpoint initialized"
        );

        Ok(Self {
            tag: config.tag.clone(),
            private_key,
            public_key,
            allowed_peers,
            preshared_key,
            listen_port,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_index: Arc::new(Mutex::new(1)),
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    fn is_peer_allowed(&self, peer_pk: &PublicKey) -> bool {
        self.allowed_peers.iter().any(|pk| pk.as_bytes() == peer_pk.as_bytes())
    }

    async fn alloc_index(&self) -> u32 {
        let mut idx = self.next_index.lock().await;
        let val = *idx;
        *idx = idx.wrapping_add(1);
        if *idx == 0 { *idx = 1; }
        val
    }

    /// 处理收到的 UDP 包
    pub async fn handle_packet(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<Option<Vec<u8>>> {
        if data.len() < 4 {
            return Ok(None);
        }

        let msg_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        match msg_type {
            1 => self.handle_handshake_init(data, peer_addr, socket).await,
            4 => self.handle_transport(data).await,
            _ => {
                debug!(msg_type, "unknown WireGuard message type");
                Ok(None)
            }
        }
    }

    async fn handle_handshake_init(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<Option<Vec<u8>>> {
        for peer_pk in &self.allowed_peers {
            let keys = WireGuardKeys {
                private_key: self.private_key.clone(),
                public_key: self.public_key,
                peer_public_key: *peer_pk,
                preshared_key: self.preshared_key,
            };

            match parse_handshake_init(data, &keys) {
                Ok((peer_sender_index, found_peer_pk, ck, h)) => {
                    if !self.is_peer_allowed(&found_peer_pk) {
                        warn!("WireGuard handshake from unknown peer");
                        continue;
                    }

                    let sender_index = self.alloc_index().await;
                    let eph_bytes: [u8; 32] = data[8..40].try_into().unwrap();

                    let (resp_msg, transport_keys) = create_handshake_resp(
                        &keys,
                        sender_index,
                        peer_sender_index,
                        ck,
                        h,
                        &eph_bytes,
                    )?;

                    let session = WgSession {
                        transport_keys,
                        peer_addr,
                        peer_public_key: found_peer_pk,
                    };

                    self.sessions.write().await.insert(sender_index, session);
                    debug!(
                        sender_index,
                        peer_index = peer_sender_index,
                        peer = %peer_addr,
                        "WireGuard handshake completed"
                    );

                    socket.send_to(&resp_msg, peer_addr).await?;
                    return Ok(None);
                }
                Err(_) => continue,
            }
        }

        warn!(peer = %peer_addr, "WireGuard handshake failed for all peers");
        Ok(None)
    }

    async fn handle_transport(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if data.len() < 16 {
            return Ok(None);
        }

        let receiver_index = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let mut sessions = self.sessions.write().await;
        let session = match sessions.get_mut(&receiver_index) {
            Some(s) => s,
            None => {
                debug!(receiver_index, "unknown session index");
                return Ok(None);
            }
        };

        match decrypt_transport(&mut session.transport_keys, data) {
            Ok(plaintext) => {
                if plaintext.is_empty() {
                    return Ok(None); // keepalive
                }
                Ok(Some(plaintext))
            }
            Err(e) => {
                debug!(error = %e, "WireGuard transport decrypt failed");
                Ok(None)
            }
        }
    }

    /// 启动 UDP 监听循环
    pub async fn run(&self) -> Result<()> {
        let bind_addr = format!("0.0.0.0:{}", self.listen_port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        info!(
            tag = self.tag.as_str(),
            addr = bind_addr.as_str(),
            "WireGuard Endpoint listening"
        );

        let socket = Arc::new(socket);
        let mut buf = vec![0u8; 65536];

        loop {
            let (n, peer_addr) = socket.recv_from(&mut buf).await?;
            let packet = &buf[..n];

            match self.handle_packet(packet, peer_addr, &socket).await {
                Ok(Some(ip_packet)) => {
                    debug!(
                        len = ip_packet.len(),
                        peer = %peer_addr,
                        "decoded WireGuard IP packet"
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    debug!(error = %e, peer = %peer_addr, "WireGuard packet error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_endpoint_peer_check() {
        let (_, pk1) = noise::generate_keypair();
        let (_, pk2) = noise::generate_keypair();
        let (priv_key, pub_key) = noise::generate_keypair();

        let ep = WireGuardEndpoint {
            tag: "test-wg".to_string(),
            private_key: priv_key,
            public_key: pub_key,
            allowed_peers: vec![pk1],
            preshared_key: [0u8; 32],
            listen_port: 51820,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_index: Arc::new(Mutex::new(1)),
        };

        assert!(ep.is_peer_allowed(&pk1));
        assert!(!ep.is_peer_allowed(&pk2));
    }
}
