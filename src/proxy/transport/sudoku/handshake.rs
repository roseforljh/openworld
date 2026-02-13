/// Sudoku 协议握手
///
/// 客户端握手流程：
/// 1. HTTP Mask（可选）：写入伪 HTTP 请求头
/// 2. 包装为 Sudoku 混淆连接
/// 3. 包装为 AEAD 加密连接
/// 4. 发送 16 字节握手 payload（8 字节时间戳 + 8 字节 key hash）
/// 5. 发送 1 字节 downlink mode
/// 6. 发送目标地址
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::conn::SudokuStream;
use super::crypto::AeadStream;
use super::httpmask;
use super::table::Table;
use crate::common::ProxyStream;

/// 握手配置
pub struct SudokuConfig {
    pub key: String,
    pub aead_method: String,
    pub table: Arc<Table>,
    pub padding_min: u8,
    pub padding_max: u8,
    pub enable_pure_downlink: bool,
    pub disable_http_mask: bool,
    pub http_mask_host: String,
    pub http_mask_path_root: String,
}

const DOWNLINK_MODE_PURE: u8 = 0x01;
const _DOWNLINK_MODE_PACKED: u8 = 0x02;

/// 客户端握手
///
/// 返回已建立加密混淆连接的 ProxyStream
pub async fn client_handshake(
    mut raw_stream: ProxyStream,
    config: &SudokuConfig,
    target_addr: &str,
    target_port: u16,
) -> anyhow::Result<ProxyStream> {
    // 1. HTTP Mask（可选）
    if !config.disable_http_mask {
        let host = if config.http_mask_host.is_empty() {
            "www.example.com"
        } else {
            &config.http_mask_host
        };
        httpmask::write_http_mask(&mut raw_stream, host, &config.http_mask_path_root).await?;
    }

    // 2. 包装为 Sudoku 混淆流
    let sudoku_stream = SudokuStream::new(
        raw_stream,
        config.table.clone(),
        config.padding_min,
        config.padding_max,
    );

    // 3. 包装为 AEAD 加密流
    let aead_seed = client_aead_seed(&config.key);
    let mut aead_stream = AeadStream::new(sudoku_stream, &aead_seed, &config.aead_method)
        .map_err(|e| anyhow::anyhow!(e))?;

    // 4. 发送握手 payload
    let payload = build_handshake_payload(&config.key);
    aead_stream.write_all(&payload).await?;

    // 5. 发送 downlink mode
    let mode = if config.enable_pure_downlink {
        DOWNLINK_MODE_PURE
    } else {
        _DOWNLINK_MODE_PACKED
    };
    aead_stream.write_all(&[mode]).await?;

    // 6. 发送目标地址
    let addr_bytes = encode_address(target_addr, target_port);
    aead_stream.write_all(&addr_bytes).await?;

    aead_stream.flush().await?;

    // 包装为 ProxyStream（Box<dyn AsyncStream>）
    Ok(Box::new(aead_stream))
}

/// 构建 16 字节握手 payload
fn build_handshake_payload(key: &str) -> [u8; 16] {
    let mut payload = [0u8; 16];

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    payload[..8].copy_from_slice(&ts.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();
    payload[8..16].copy_from_slice(&hash[..8]);

    payload
}

/// 客户端 AEAD 种子
fn client_aead_seed(key: &str) -> String {
    key.to_string()
}

/// 编码目标地址
/// 格式：[1 byte type][address][2 byte port]
fn encode_address(addr: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();

    if let Ok(ipv4) = addr.parse::<std::net::Ipv4Addr>() {
        buf.push(0x01);
        buf.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = addr.parse::<std::net::Ipv6Addr>() {
        buf.push(0x04);
        buf.extend_from_slice(&ipv6.octets());
    } else {
        buf.push(0x03);
        let domain_bytes = addr.as_bytes();
        buf.push(domain_bytes.len() as u8);
        buf.extend_from_slice(domain_bytes);
    }

    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_payload_format() {
        let payload = build_handshake_payload("test-key");
        assert_eq!(payload.len(), 16);
        let ts = u64::from_be_bytes(payload[..8].try_into().unwrap());
        assert!(ts > 1577836800);
    }

    #[test]
    fn encode_domain_address() {
        let bytes = encode_address("example.com", 443);
        assert_eq!(bytes[0], 0x03);
        assert_eq!(bytes[1], 11);
        assert_eq!(&bytes[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([bytes[13], bytes[14]]), 443);
    }

    #[test]
    fn encode_ipv4_address() {
        let bytes = encode_address("127.0.0.1", 8080);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([bytes[5], bytes[6]]), 8080);
    }
}
