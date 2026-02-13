// DERP 服务端
//
// 实现 Tailscale 兼容的 DERP 中继服务：
// - HTTP 升级到 DERP 二进制协议
// - NaCl box 认证（客户端用 curve25519 公钥证明身份）
// - 按公钥路由包（SendPacket → RecvPacket）
// - KeepAlive / Ping / Pong 心跳

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SecretKey, SalsaBox,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use super::protocol::*;

/// 发往客户端的消息
#[derive(Debug)]
enum ClientMsg {
    /// 转发包：源公钥 + 数据
    Packet {
        src_key: [u8; KEY_LEN],
        data: Vec<u8>,
    },
    /// 通知某 peer 离开
    PeerGone {
        key: [u8; KEY_LEN],
        reason: PeerGoneReason,
    },
    /// 健康状态
    #[allow(dead_code)]
    Health(String),
    /// 关闭连接
    Shutdown,
}

/// 已连接客户端
struct ConnectedClient {
    /// 发送通道
    tx: mpsc::Sender<ClientMsg>,
    /// 是否标记为首选节点
    preferred: bool,
}

/// DERP 服务端
pub struct DerpServer {
    /// 服务端 curve25519 密钥对
    secret_key: SecretKey,
    public_key: PublicKey,
    /// 已连接客户端（公钥 → 客户端信息）
    clients: Arc<RwLock<HashMap<[u8; KEY_LEN], ConnectedClient>>>,
}

impl DerpServer {
    /// 创建新的 DERP 服务端
    pub fn new() -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();
        info!("DERP 服务端已创建，公钥: {:?}", public_key.as_bytes());
        Self {
            secret_key,
            public_key,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 从已有私钥创建
    pub fn with_key(secret_key_bytes: [u8; 32]) -> Self {
        let secret_key = SecretKey::from(secret_key_bytes);
        let public_key = secret_key.public_key();
        info!("DERP 服务端已创建（已有密钥），公钥: {:?}", public_key.as_bytes());
        Self {
            secret_key,
            public_key,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 获取服务端公钥字节
    pub fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        *self.public_key.as_bytes()
    }

    /// 处理一个新客户端连接
    ///
    /// 该方法在 HTTP 升级后调用，接管底层 TCP 流。
    pub async fn handle_client<S>(&self, mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // ===== 1. 发送 ServerKey =====
        let server_key_payload = build_server_key(self.public_key.as_bytes());
        if let Err(e) = write_frame(&mut stream, FrameType::ServerKey, &server_key_payload).await {
            warn!("发送 ServerKey 失败: {}", e);
            return;
        }

        // ===== 2. 接收 ClientInfo =====
        let (ft, payload) = match read_frame(&mut stream).await {
            Ok(f) => f,
            Err(e) => {
                warn!("读取 ClientInfo 失败: {}", e);
                return;
            }
        };

        if ft != FrameType::ClientInfo {
            warn!("期望 ClientInfo 帧，收到 {:?}", ft);
            return;
        }

        let (client_pub_bytes, nonce_bytes, ciphertext) = match parse_client_info(&payload) {
            Ok(v) => v,
            Err(e) => {
                warn!("解析 ClientInfo 失败: {}", e);
                return;
            }
        };

        // 解密 ClientInfo JSON（使用 NaCl box）
        let client_pub = PublicKey::from(client_pub_bytes);
        let salsa_box = SalsaBox::new(&client_pub, &self.secret_key);
        let nonce = crypto_box::Nonce::from(nonce_bytes);

        let _client_info_json = match salsa_box.decrypt(&nonce, ciphertext) {
            Ok(plaintext) => {
                match serde_json::from_slice::<ClientInfoJson>(&plaintext) {
                    Ok(info) => {
                        debug!("客户端 {:?} 已认证，版本: {}", &client_pub_bytes[..4], info.version);
                        info
                    }
                    Err(e) => {
                        warn!("解析 ClientInfo JSON 失败: {}", e);
                        // 容忍解析失败，使用默认值
                        ClientInfoJson { version: 0 }
                    }
                }
            }
            Err(e) => {
                warn!("解密 ClientInfo 失败: {:?}", e);
                return;
            }
        };

        // ===== 3. 发送 ServerInfo =====
        let server_info = ServerInfoJson::default();
        let server_info_json = serde_json::to_vec(&server_info).unwrap();

        let si_nonce = SalsaBox::generate_nonce(&mut OsRng);
        let sealed = salsa_box.encrypt(&si_nonce, server_info_json.as_ref())
            .expect("加密 ServerInfo 失败");
        let nonce_bytes: [u8; NONCE_LEN] = si_nonce.into();
        let server_info_payload = build_server_info(&nonce_bytes, &sealed);

        if let Err(e) = write_frame(&mut stream, FrameType::ServerInfo, &server_info_payload).await {
            warn!("发送 ServerInfo 失败: {}", e);
            return;
        }
        if let Err(e) = stream.flush().await {
            warn!("flush 失败: {}", e);
            return;
        }

        info!("DERP 客户端已连接：{:02x}{:02x}{:02x}{:02x}...",
            client_pub_bytes[0], client_pub_bytes[1], client_pub_bytes[2], client_pub_bytes[3]);

        // ===== 4. 注册客户端 + 进入稳态 =====
        let (tx, rx) = mpsc::channel::<ClientMsg>(256);

        {
            let mut clients = self.clients.write().await;
            // 如果同一公钥已连接，关闭旧连接
            if let Some(old) = clients.remove(&client_pub_bytes) {
                let _ = old.tx.send(ClientMsg::Shutdown).await;
            }
            clients.insert(client_pub_bytes, ConnectedClient {
                tx: tx.clone(),
                preferred: false,
            });
        }

        // 通知其他客户端此 peer 上线
        self.broadcast_peer_present(&client_pub_bytes).await;

        // 运行稳态事件循环
        self.client_loop(&mut stream, client_pub_bytes, rx).await;

        // ===== 5. 清理 =====
        {
            let mut clients = self.clients.write().await;
            clients.remove(&client_pub_bytes);
        }
        // 通知其他客户端此 peer 离开
        self.broadcast_peer_gone(&client_pub_bytes).await;

        info!("DERP 客户端已断开：{:02x}{:02x}{:02x}{:02x}...",
            client_pub_bytes[0], client_pub_bytes[1], client_pub_bytes[2], client_pub_bytes[3]);
    }

    /// 稳态事件循环：同时处理客户端读写和内部消息
    async fn client_loop<S>(
        &self,
        stream: &mut S,
        client_key: [u8; KEY_LEN],
        mut rx: mpsc::Receiver<ClientMsg>,
    )
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut keepalive_timer = interval(Duration::from_secs(KEEP_ALIVE_SECS));
        let (mut reader, mut writer) = tokio::io::split(stream);

        loop {
            tokio::select! {
                // 1. 从客户端读帧
                frame_result = read_frame(&mut reader) => {
                    match frame_result {
                        Ok((frame_type, payload)) => {
                            if let Err(e) = self.handle_client_frame(
                                &client_key, frame_type, &payload, &mut writer
                            ).await {
                                warn!("处理客户端帧失败: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                warn!("读取客户端帧出错: {}", e);
                            }
                            break;
                        }
                    }
                }
                // 2. 从内部通道接收消息（转发/通知）
                msg = rx.recv() => {
                    match msg {
                        Some(ClientMsg::Packet { src_key, data }) => {
                            let payload = build_recv_packet(&src_key, &data);
                            if let Err(e) = write_frame(&mut writer, FrameType::RecvPacket, &payload).await {
                                warn!("转发包失败: {}", e);
                                break;
                            }
                        }
                        Some(ClientMsg::PeerGone { key, reason }) => {
                            let payload = build_peer_gone(&key, reason);
                            let _ = write_frame(&mut writer, FrameType::PeerGone, &payload).await;
                        }
                        Some(ClientMsg::Health(msg)) => {
                            let _ = write_frame(&mut writer, FrameType::Health, msg.as_bytes()).await;
                        }
                        Some(ClientMsg::Shutdown) | None => {
                            break;
                        }
                    }
                }
                // 3. KeepAlive 定时器
                _ = keepalive_timer.tick() => {
                    if let Err(e) = write_frame(&mut writer, FrameType::KeepAlive, &[]).await {
                        warn!("发送 KeepAlive 失败: {}", e);
                        break;
                    }
                }
            }
        }
    }

    /// 处理客户端发来的帧
    async fn handle_client_frame<W>(
        &self,
        src_key: &[u8; KEY_LEN],
        frame_type: FrameType,
        payload: &[u8],
        writer: &mut W,
    ) -> io::Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        match frame_type {
            FrameType::SendPacket => {
                let (dst_key, data) = parse_send_packet(payload)?;
                self.forward_packet(src_key, &dst_key, data).await;
            }
            FrameType::Ping => {
                // 回 Pong
                write_frame(writer, FrameType::Pong, payload).await?;
            }
            FrameType::Pong => {
                // 收到 Pong，忽略
            }
            FrameType::NotePreferred => {
                if !payload.is_empty() {
                    let preferred = payload[0] != 0;
                    let mut clients = self.clients.write().await;
                    if let Some(client) = clients.get_mut(src_key) {
                        client.preferred = preferred;
                    }
                }
            }
            FrameType::KeepAlive => {
                // 客户端 keepalive，忽略
            }
            _ => {
                debug!("忽略未处理的帧类型: {:?}", frame_type);
            }
        }
        Ok(())
    }

    /// 转发包到目标客户端
    async fn forward_packet(&self, src_key: &[u8; KEY_LEN], dst_key: &[u8; KEY_LEN], data: &[u8]) {
        let clients = self.clients.read().await;
        if let Some(dst_client) = clients.get(dst_key) {
            let msg = ClientMsg::Packet {
                src_key: *src_key,
                data: data.to_vec(),
            };
            if dst_client.tx.try_send(msg).is_err() {
                debug!("目标客户端 {:02x}{:02x}... 缓冲区已满", dst_key[0], dst_key[1]);
            }
        } else {
            // 目标不在线 — 回复 PeerGone
            if let Some(src_client) = clients.get(src_key) {
                let _ = src_client.tx.try_send(ClientMsg::PeerGone {
                    key: *dst_key,
                    reason: PeerGoneReason::NotHere,
                });
            }
        }
    }

    /// 广播 Peer 上线
    async fn broadcast_peer_present(&self, new_key: &[u8; KEY_LEN]) {
        let clients = self.clients.read().await;
        for (key, client) in clients.iter() {
            if key != new_key {
                // 简易 PeerPresent：仅发送 32 字节公钥
                let _ = client.tx.try_send(ClientMsg::Packet {
                    src_key: *new_key,
                    data: Vec::new(), // 空数据表示 PeerPresent
                });
            }
        }
    }

    /// 广播 Peer 离线
    async fn broadcast_peer_gone(&self, gone_key: &[u8; KEY_LEN]) {
        let clients = self.clients.read().await;
        for (key, client) in clients.iter() {
            if key != gone_key {
                let _ = client.tx.try_send(ClientMsg::PeerGone {
                    key: *gone_key,
                    reason: PeerGoneReason::Disconnected,
                });
            }
        }
    }

    /// 获取当前在线客户端数量
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// 获取所有在线客户端公钥
    pub async fn online_keys(&self) -> Vec<[u8; KEY_LEN]> {
        self.clients.read().await.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derp_server_creation() {
        let server = DerpServer::new();
        let pk = server.public_key_bytes();
        assert_eq!(pk.len(), KEY_LEN);
        // 公钥不应全为零
        assert_ne!(pk, [0u8; KEY_LEN]);
    }

    #[test]
    fn test_derp_server_with_key() {
        let key_bytes = [42u8; 32];
        let server = DerpServer::with_key(key_bytes);
        let pk = server.public_key_bytes();
        assert_eq!(pk.len(), KEY_LEN);
        assert_ne!(pk, [0u8; KEY_LEN]);
    }

    #[tokio::test]
    async fn test_client_count() {
        let server = DerpServer::new();
        assert_eq!(server.client_count().await, 0);
    }
}
