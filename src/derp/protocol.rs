// DERP 服务 — 协议层
//
// 实现 Tailscale DERP（Designated Encrypted Relay for Packets）协议。
// 参考：https://pkg.go.dev/tailscale.com/derp
//
// 帧格式：[1字节类型][4字节大端长度][payload]
// 认证：NaCl box（crypto_box）
// 寻址：curve25519 公钥（32字节）

use std::io;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ========== 常量 ==========

/// DERP 魔术字节 "DERP🔑" (8 字节)
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";

/// 协议版本
pub const PROTOCOL_VERSION: u8 = 2;

/// 帧头长度：1字节类型 + 4字节大端长度
pub const FRAME_HEADER_LEN: usize = 5;

/// 密钥长度（curve25519 公钥）
pub const KEY_LEN: usize = 32;

/// Nonce 长度（NaCl box）
pub const NONCE_LEN: usize = 24;

/// 最大包大小 (64 KiB)
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// 最大帧大小（含帧头）
pub const MAX_FRAME_SIZE: usize = 1 << 20;

/// KeepAlive 间隔（秒）
pub const KEEP_ALIVE_SECS: u64 = 60;

/// Ping 载荷大小
pub const PING_LEN: usize = 8;

/// FastStart HTTP 请求头
pub const FAST_START_HEADER: &str = "Derp-Fast-Start";

/// DERP HTTP 升级协议名
pub const UPGRADE_PROTOCOL: &str = "DERP";

// ========== 帧类型 ==========

/// DERP 帧类型（1字节）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// 服务端 → 客户端：8字节 Magic + 32字节服务端公钥
    ServerKey = 0x01,
    /// 客户端 → 服务端：32字节公钥 + 24字节 nonce + naclbox(json)
    ClientInfo = 0x02,
    /// 服务端 → 客户端：24字节 nonce + naclbox(json)
    ServerInfo = 0x03,
    /// 客户端 → 服务端：32字节目标公钥 + 包数据
    SendPacket = 0x04,
    /// 服务端 → 客户端：v2 为 32字节源公钥 + 包数据
    RecvPacket = 0x05,
    /// 服务端 → 客户端：无载荷，心跳
    KeepAlive = 0x06,
    /// 客户端 → 服务端：1字节（是否首选节点）
    NotePreferred = 0x07,
    /// 服务端 → 客户端：32字节公钥 + 1字节原因
    PeerGone = 0x08,
    /// 服务端 → 客户端：32字节公钥 + 可选 IP/端口
    PeerPresent = 0x09,
    /// 服务端间转发：32字节源 + 32字节目标 + 数据
    ForwardPacket = 0x0A,
    /// Mesh 监听连接变化
    WatchConns = 0x10,
    /// 关闭指定 peer 连接
    ClosePeer = 0x11,
    /// 客户端 ↔ 服务端：8字节 ping 载荷
    Ping = 0x12,
    /// 客户端 ↔ 服务端：8字节 pong 回应
    Pong = 0x13,
    /// 服务端 → 客户端：连接健康状态文本
    Health = 0x14,
    /// 服务端 → 客户端：重启通知
    Restarting = 0x15,
}

impl FrameType {
    /// 从 u8 解析帧类型
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::ServerKey),
            0x02 => Some(Self::ClientInfo),
            0x03 => Some(Self::ServerInfo),
            0x04 => Some(Self::SendPacket),
            0x05 => Some(Self::RecvPacket),
            0x06 => Some(Self::KeepAlive),
            0x07 => Some(Self::NotePreferred),
            0x08 => Some(Self::PeerGone),
            0x09 => Some(Self::PeerPresent),
            0x0A => Some(Self::ForwardPacket),
            0x10 => Some(Self::WatchConns),
            0x11 => Some(Self::ClosePeer),
            0x12 => Some(Self::Ping),
            0x13 => Some(Self::Pong),
            0x14 => Some(Self::Health),
            0x15 => Some(Self::Restarting),
            _ => None,
        }
    }
}

// ========== PeerGone 原因 ==========

/// 节点离开原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerGoneReason {
    /// 正常断开
    Disconnected = 0x00,
    /// 服务端不知道此节点
    NotHere = 0x01,
}

// ========== 帧读写 ==========

/// 写入帧头 + 载荷
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    frame_type: FrameType,
    payload: &[u8],
) -> io::Result<()> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = frame_type as u8;
    let len = payload.len() as u32;
    header[1..5].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    Ok(())
}

/// 读取一帧（帧类型 + 载荷）
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> io::Result<(FrameType, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut header).await?;

    let frame_type = FrameType::from_u8(header[0]).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("未知帧类型: 0x{:02x}", header[0]))
    })?;

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("帧过大: {} > {}", len, MAX_FRAME_SIZE),
        ));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }

    Ok((frame_type, payload))
}

// ========== 特定帧构建 ==========

/// 构建 ServerKey 帧载荷：8字节 Magic + 32字节服务端公钥
pub fn build_server_key(server_public_key: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAGIC.len() + KEY_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(server_public_key);
    buf
}

/// 解析 ServerKey 帧载荷 → 服务端公钥
pub fn parse_server_key(payload: &[u8]) -> io::Result<[u8; KEY_LEN]> {
    if payload.len() < MAGIC.len() + KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerKey 帧载荷过短",
        ));
    }
    if &payload[..MAGIC.len()] != MAGIC.as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Magic 不匹配",
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN]);
    Ok(key)
}

/// 构建 ClientInfo 帧载荷：32字节公钥 + 24字节 nonce + naclbox(json)
pub fn build_client_info(
    client_public_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed_json: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_LEN + NONCE_LEN + sealed_json.len());
    buf.extend_from_slice(client_public_key);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(sealed_json);
    buf
}

/// 解析 ClientInfo 帧载荷 → (公钥, nonce, 密文)
pub fn parse_client_info(payload: &[u8]) -> io::Result<([u8; KEY_LEN], [u8; NONCE_LEN], &[u8])> {
    if payload.len() < KEY_LEN + NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ClientInfo 帧载荷过短",
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[..KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[KEY_LEN..KEY_LEN + NONCE_LEN]);
    let ciphertext = &payload[KEY_LEN + NONCE_LEN..];
    Ok((key, nonce, ciphertext))
}

/// 构建 ServerInfo 帧载荷：24字节 nonce + naclbox(json)
pub fn build_server_info(
    nonce: &[u8; NONCE_LEN],
    sealed_json: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NONCE_LEN + sealed_json.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(sealed_json);
    buf
}

/// 解析 ServerInfo 帧载荷 → (nonce, 密文)
pub fn parse_server_info(payload: &[u8]) -> io::Result<([u8; NONCE_LEN], &[u8])> {
    if payload.len() < NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerInfo 帧载荷过短",
        ));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    Ok((nonce, &payload[NONCE_LEN..]))
}

/// 构建 SendPacket 帧载荷：32字节目标公钥 + 数据
pub fn build_send_packet(dst_key: &[u8; KEY_LEN], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_LEN + data.len());
    buf.extend_from_slice(dst_key);
    buf.extend_from_slice(data);
    buf
}

/// 解析 SendPacket 帧载荷 → (目标公钥, 数据)
pub fn parse_send_packet(payload: &[u8]) -> io::Result<([u8; KEY_LEN], &[u8])> {
    if payload.len() < KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SendPacket 帧载荷过短",
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[..KEY_LEN]);
    Ok((key, &payload[KEY_LEN..]))
}

/// 构建 RecvPacket 帧载荷 (v2)：32字节源公钥 + 数据
pub fn build_recv_packet(src_key: &[u8; KEY_LEN], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_LEN + data.len());
    buf.extend_from_slice(src_key);
    buf.extend_from_slice(data);
    buf
}

/// 解析 RecvPacket 帧载荷 (v2) → (源公钥, 数据)
pub fn parse_recv_packet(payload: &[u8]) -> io::Result<([u8; KEY_LEN], &[u8])> {
    if payload.len() < KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RecvPacket 帧过短（v2 需要源公钥）",
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[..KEY_LEN]);
    Ok((key, &payload[KEY_LEN..]))
}

/// 构建 PeerGone 帧载荷：32字节公钥 + 1字节原因
pub fn build_peer_gone(key: &[u8; KEY_LEN], reason: PeerGoneReason) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_LEN + 1);
    buf.extend_from_slice(key);
    buf.push(reason as u8);
    buf
}

/// 构建 Ping 帧载荷：8字节随机数据
pub fn build_ping() -> [u8; PING_LEN] {
    let mut ping = [0u8; PING_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut ping);
    ping
}

/// 构建 Restarting 帧载荷：2个大端 u32（重连延迟 ms + 总尝试时间 ms）
pub fn build_restarting(reconnect_ms: u32, try_for_ms: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.put_u32(reconnect_ms);
    buf.put_u32(try_for_ms);
    buf
}

/// 解析 Restarting 帧载荷 → (重连延迟 ms, 总尝试时间 ms)
pub fn parse_restarting(payload: &[u8]) -> io::Result<(u32, u32)> {
    if payload.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Restarting 帧载荷过短",
        ));
    }
    let mut buf = &payload[..8];
    let reconnect = buf.get_u32();
    let try_for = buf.get_u32();
    Ok((reconnect, try_for))
}

// ========== 客户端信息 JSON ==========

/// 客户端信息（在 ClientInfo 帧中加密传输）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientInfoJson {
    /// 客户端版本
    #[serde(default)]
    pub version: u8,
}

/// 服务端信息（在 ServerInfo 帧中加密传输）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerInfoJson {
    /// 令牌桶速率（未使用，保留字段）
    #[serde(default, rename = "tokenBucketBytesPerSecond")]
    pub token_bucket_bytes_per_sec: u64,
    /// 令牌桶大小
    #[serde(default, rename = "tokenBucketBytesBurst")]
    pub token_bucket_bytes_burst: u64,
}

impl Default for ServerInfoJson {
    fn default() -> Self {
        Self {
            token_bucket_bytes_per_sec: 0,
            token_bucket_bytes_burst: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        for &ft in &[
            FrameType::ServerKey,
            FrameType::ClientInfo,
            FrameType::ServerInfo,
            FrameType::SendPacket,
            FrameType::RecvPacket,
            FrameType::KeepAlive,
            FrameType::Ping,
            FrameType::Pong,
            FrameType::Health,
            FrameType::Restarting,
        ] {
            assert_eq!(FrameType::from_u8(ft as u8), Some(ft));
        }
        // 未知帧类型
        assert_eq!(FrameType::from_u8(0xFF), None);
    }

    #[test]
    fn test_server_key_build_parse() {
        let key = [42u8; KEY_LEN];
        let payload = build_server_key(&key);
        assert_eq!(payload.len(), MAGIC.len() + KEY_LEN);
        let parsed = parse_server_key(&payload).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_server_key_bad_magic() {
        let mut payload = build_server_key(&[0u8; KEY_LEN]);
        payload[0] = 0xFF; // 破坏 magic
        assert!(parse_server_key(&payload).is_err());
    }

    #[test]
    fn test_client_info_build_parse() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let sealed = b"encrypted_json_data";
        let payload = build_client_info(&key, &nonce, sealed);
        let (pk, n, ct) = parse_client_info(&payload).unwrap();
        assert_eq!(pk, key);
        assert_eq!(n, nonce);
        assert_eq!(ct, sealed);
    }

    #[test]
    fn test_send_packet_build_parse() {
        let dst = [3u8; KEY_LEN];
        let data = b"wireguard_encrypted_packet";
        let payload = build_send_packet(&dst, data);
        let (k, d) = parse_send_packet(&payload).unwrap();
        assert_eq!(k, dst);
        assert_eq!(d, data);
    }

    #[test]
    fn test_recv_packet_build_parse() {
        let src = [4u8; KEY_LEN];
        let data = b"response_packet";
        let payload = build_recv_packet(&src, data);
        let (k, d) = parse_recv_packet(&payload).unwrap();
        assert_eq!(k, src);
        assert_eq!(d, data);
    }

    #[test]
    fn test_restarting_build_parse() {
        let payload = build_restarting(5000, 30000);
        let (reconnect, try_for) = parse_restarting(&payload).unwrap();
        assert_eq!(reconnect, 5000);
        assert_eq!(try_for, 30000);
    }

    #[test]
    fn test_server_info_json() {
        let info = ServerInfoJson::default();
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ServerInfoJson = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token_bucket_bytes_per_sec, 0);
    }

    #[tokio::test]
    async fn test_frame_write_read() {
        let payload = b"hello derp";
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameType::Health, payload).await.unwrap();

        let mut cursor = io::Cursor::new(buf);
        let (ft, data) = read_frame(&mut cursor).await.unwrap();
        assert_eq!(ft, FrameType::Health);
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn test_frame_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameType::KeepAlive, &[]).await.unwrap();

        let mut cursor = io::Cursor::new(buf);
        let (ft, data) = read_frame(&mut cursor).await.unwrap();
        assert_eq!(ft, FrameType::KeepAlive);
        assert!(data.is_empty());
    }
}
