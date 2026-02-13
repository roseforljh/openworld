/// ShadowTLS v3 传输层（客户端出站）
///
/// 协议流程：
///   1. TCP 连接到 ShadowTLS 服务器
///   2. TLS 握手（自定义 SessionID 含 HMAC 签名）
///   3. 提取 ServerRandom，建立 HMAC 帧封装数据通道
///
/// 帧格式：(5B TLS ApplicationData header)(4B HMAC)(data)
use std::io;

use anyhow::{bail, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use super::StreamTransport;
use crate::common::{Address, DialerConfig, ProxyStream};

type HmacSha256 = Hmac<Sha256>;

// TLS 常量
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_ALERT: u8 = 0x15;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// ShadowTLS v3 传输
pub struct ShadowTlsTransport {
    server_addr: String,
    server_port: u16,
    password: String,
    sni: String,
    dialer_config: Option<DialerConfig>,
}

impl ShadowTlsTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        password: String,
        sni: String,
        dialer_config: Option<DialerConfig>,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            password,
            sni,
            dialer_config,
        }
    }
}

#[async_trait]
impl StreamTransport for ShadowTlsTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let mut tcp = super::dial_tcp(
            &self.server_addr,
            self.server_port,
            &self.dialer_config,
            None,
        )
        .await?;

        // === 阶段 1: TLS 握手 ===
        let server_random = do_shadow_tls_handshake(&mut tcp, &self.sni, &self.password).await?;

        debug!(sni = self.sni, "ShadowTLS v3 handshake completed");

        // === 阶段 2: 数据传输 (duplex channel) ===
        let hmac_client = new_hmac(&self.password, &server_random, b"C")?;
        let hmac_server = new_hmac(&self.password, &server_random, b"S")?;
        let hmac_verify =
            HmacSha256::new_from_slice(&server_random).map_err(|e| anyhow::anyhow!("{}", e))?;

        // 使用 duplex channel：用户侧得到 user_stream，后台任务操作 proxy_stream
        let (user_stream, proxy_stream) = tokio::io::duplex(64 * 1024);
        let (tcp_read, tcp_write) = tokio::io::split(tcp);
        let (proxy_read, proxy_write) = tokio::io::split(proxy_stream);

        // 后台任务：从 TCP 读取帧 → 解封 → 写入 proxy_write (用户读)
        tokio::spawn(async move {
            if let Err(e) = read_loop(tcp_read, proxy_write, hmac_server, hmac_verify).await {
                debug!(error = %e, "ShadowTLS read loop ended");
            }
        });

        // 后台任务：从 proxy_read (用户写) → 封帧 → 写入 TCP
        tokio::spawn(async move {
            if let Err(e) = write_loop(proxy_read, tcp_write, hmac_client).await {
                debug!(error = %e, "ShadowTLS write loop ended");
            }
        });

        Ok(Box::new(user_stream))
    }
}

/// 执行 ShadowTLS v3 握手：从 ClientHello 到握手完成，返回 ServerRandom
async fn do_shadow_tls_handshake(
    tcp: &mut tokio::net::TcpStream,
    sni: &str,
    password: &str,
) -> Result<[u8; 32]> {
    use std::sync::Arc;

    // 构建 TLS ClientConfig
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut tls_conn = rustls::ClientConnection::new(
        Arc::new(tls_config),
        rustls::pki_types::ServerName::try_from(sni.to_string())?,
    )?;

    // 取出 ClientHello
    let mut client_hello_buf = Vec::new();
    tls_conn.write_tls(&mut client_hello_buf)?;

    // 签名 SessionID
    let signed = sign_client_hello(&client_hello_buf, password)?;
    tcp.write_all(&signed).await?;

    // 读取并跟踪握手
    let mut server_random = [0u8; 32];
    let mut got_random = false;

    loop {
        // 先尝试发送 rustls 产生的数据
        if tls_conn.wants_write() {
            let mut buf = Vec::new();
            tls_conn.write_tls(&mut buf)?;
            if !buf.is_empty() {
                tcp.write_all(&buf).await?;
            }
        }

        if !tls_conn.is_handshaking() {
            break;
        }

        if !tls_conn.wants_read() {
            break;
        }

        // 读取 TLS record
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header).await?;
        let length = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut payload = vec![0u8; length];
        tcp.read_exact(&mut payload).await?;

        // 提取 ServerRandom
        if !got_random && header[0] == TLS_HANDSHAKE {
            if let Some(random) = extract_server_random(&payload) {
                server_random = random;
                got_random = true;
            }
        }

        // 喂给 rustls
        let mut record = Vec::with_capacity(5 + length);
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);
        tls_conn.read_tls(&mut &record[..])?;

        match tls_conn.process_new_packets() {
            Ok(_) => {}
            Err(e) => {
                // ShadowTLS 服务端可能会修改 ApplicationData，rustls 验证会失败
                // 这是协议预期行为
                debug!(error = %e, "TLS processing error (expected for ShadowTLS)");
                break;
            }
        }
    }

    // 发送剩余数据
    if tls_conn.wants_write() {
        let mut buf = Vec::new();
        tls_conn.write_tls(&mut buf)?;
        if !buf.is_empty() {
            tcp.write_all(&buf).await?;
        }
    }

    if !got_random {
        bail!("failed to extract ServerRandom from handshake");
    }

    Ok(server_random)
}

/// 从 TLS handshake payload 中提取 ServerRandom
fn extract_server_random(payload: &[u8]) -> Option<[u8; 32]> {
    // Handshake: type(1) + length(3) + version(2) + random(32)
    if payload.len() >= 4 && payload[0] == HANDSHAKE_SERVER_HELLO {
        let body_start = 4; // skip type + length
        if payload.len() >= body_start + 2 + 32 {
            let mut random = [0u8; 32];
            random.copy_from_slice(&payload[body_start + 2..body_start + 2 + 32]);
            return Some(random);
        }
    }
    None
}

/// 修改 ClientHello 中 SessionID 的最后 4 字节为 HMAC 签名
fn sign_client_hello(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut result = data.to_vec();

    if result.len() < 5 || result[0] != TLS_HANDSHAKE {
        bail!("not a TLS handshake record");
    }

    let payload_start = 5;
    if result.len() < payload_start + 4 || result[payload_start] != HANDSHAKE_CLIENT_HELLO {
        bail!("not a ClientHello");
    }

    // ClientHello: version(2) + random(32) + session_id_len(1) + session_id(N) + ...
    let hello_body_start = payload_start + 4;
    let sid_len_offset = hello_body_start + 2 + 32;
    if result.len() <= sid_len_offset {
        bail!("ClientHello too short");
    }

    let sid_len = result[sid_len_offset] as usize;
    if sid_len < 32 {
        bail!("SessionID too short: {}", sid_len);
    }

    let sid_start = sid_len_offset + 1;
    if result.len() < sid_start + sid_len {
        bail!("ClientHello truncated");
    }

    // 清零最后 4 字节后计算 HMAC
    for i in 0..4 {
        result[sid_start + 28 + i] = 0;
    }

    let mut mac =
        HmacSha256::new_from_slice(password.as_bytes()).map_err(|e| anyhow::anyhow!("{}", e))?;
    mac.update(&result[payload_start..]);
    let sig = mac.finalize().into_bytes();

    result[sid_start + 28..sid_start + 32].copy_from_slice(&sig[..4]);
    Ok(result)
}

/// 创建 HMAC 实例: key=password, init with ServerRandom + suffix
fn new_hmac(password: &str, server_random: &[u8; 32], suffix: &[u8]) -> Result<HmacSha256> {
    let mut mac =
        HmacSha256::new_from_slice(password.as_bytes()).map_err(|e| anyhow::anyhow!("{}", e))?;
    mac.update(server_random);
    mac.update(suffix);
    Ok(mac)
}

/// 后台读取循环：从 TCP 读取 TLS 帧，解封后写入 duplex 管道
async fn read_loop<R, W>(
    mut tcp_read: R,
    mut user_write: W,
    mut hmac_data: HmacSha256,
    mut hmac_handshake: HmacSha256,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut verify_active = true;

    loop {
        // 读取 TLS record header
        let mut header = [0u8; 5];
        match tcp_read.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let record_type = header[0];
        let length = ((header[3] as usize) << 8) | (header[4] as usize);

        if length == 0 {
            continue;
        }

        let mut payload = vec![0u8; length];
        tcp_read.read_exact(&mut payload).await?;

        if record_type == TLS_ALERT {
            break;
        }

        if record_type != TLS_APPLICATION_DATA || payload.len() < 4 {
            continue;
        }

        let hmac_prefix = &payload[..4];
        let data = &payload[4..];

        // 验证 HMAC_ServerRandom+"S" (我们的数据帧)
        let mut check = hmac_data.clone();
        check.update(data);
        let expected = check.finalize().into_bytes();

        if hmac_prefix == &expected[..4] {
            // 数据帧，更新 HMAC 状态
            hmac_data.update(data);
            hmac_data.update(hmac_prefix);
            verify_active = false;

            user_write.write_all(data).await?;
            continue;
        }

        // 验证 HMAC_ServerRandom (握手残余帧)
        if verify_active {
            let mut check_h = hmac_handshake.clone();
            check_h.update(data);
            let expected_h = check_h.finalize().into_bytes();

            if hmac_prefix == &expected_h[..4] {
                // 握手残余，更新 HMAC 并丢弃
                hmac_handshake.update(data);
                hmac_handshake.update(hmac_prefix);
                continue;
            }
        }

        // HMAC 验证失败
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS HMAC verification failed",
        ));
    }

    let _ = user_write.shutdown().await;
    Ok(())
}

/// 后台写入循环：从 duplex 管道读取数据，封帧后写入 TCP
async fn write_loop<R, W>(
    mut user_read: R,
    mut tcp_write: W,
    mut hmac_write: HmacSha256,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 16384];

    loop {
        let n = match user_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        let data = &buf[..n];

        // 计算 HMAC
        let mut check = hmac_write.clone();
        check.update(data);
        let hmac_result = check.finalize().into_bytes();
        let hmac_prefix = &hmac_result[..4];

        // 更新 HMAC 状态
        hmac_write.update(data);
        hmac_write.update(hmac_prefix);

        // 构建 ApplicationData 帧
        let total_payload = 4 + data.len();
        let mut frame = Vec::with_capacity(5 + total_payload);
        frame.push(TLS_APPLICATION_DATA);
        frame.push(0x03);
        frame.push(0x03);
        frame.push((total_payload >> 8) as u8);
        frame.push(total_payload as u8);
        frame.extend_from_slice(hmac_prefix);
        frame.extend_from_slice(data);

        tcp_write.write_all(&frame).await?;
        tcp_write.flush().await?;
    }

    let _ = tcp_write.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_client_hello_rejects_non_tls() {
        let data = vec![0x00, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(sign_client_hello(&data, "test").is_err());
    }

    #[test]
    fn test_hmac_instances() {
        let sr = [0x42u8; 32];
        assert!(new_hmac("pw", &sr, b"C").is_ok());
        assert!(new_hmac("pw", &sr, b"S").is_ok());
    }

    #[test]
    fn test_extract_server_random() {
        // 构造一个最小 ServerHello payload
        let mut payload = vec![0u8; 100];
        payload[0] = HANDSHAKE_SERVER_HELLO; // type
        payload[1] = 0; // length (3 bytes)
        payload[2] = 0;
        payload[3] = 90;
        payload[4] = 0x03; // version
        payload[5] = 0x03;
        // random: bytes 6..38
        for i in 0..32 {
            payload[6 + i] = (i + 1) as u8;
        }

        let random = extract_server_random(&payload);
        assert!(random.is_some());
        let random = random.unwrap();
        for i in 0..32 {
            assert_eq!(random[i], (i + 1) as u8);
        }
    }

    #[test]
    fn test_extract_server_random_wrong_type() {
        let mut payload = vec![0u8; 50];
        payload[0] = 0x01;
        payload[3] = 10;
        payload[4] = 0x03;
        payload[5] = 0x03;
        assert!(extract_server_random(&payload).is_none());
    }

    #[test]
    fn test_transport_creation() {
        let t = ShadowTlsTransport::new(
            "1.2.3.4".to_string(),
            443,
            "secret".to_string(),
            "example.com".to_string(),
            None,
        );
        assert_eq!(t.server_addr, "1.2.3.4");
        assert_eq!(t.password, "secret");
        assert_eq!(t.sni, "example.com");
    }

    #[tokio::test]
    async fn test_read_write_loop_roundtrip() {
        let sr = [0xABu8; 32];
        let password = "test_password";

        // write_loop 使用 HMAC_C 封帧，read_loop 也必须使用相同的 HMAC_C 来验证
        let hmac_write = new_hmac(password, &sr, b"C").unwrap();
        let hmac_read = new_hmac(password, &sr, b"C").unwrap(); // 同方向
        let hmac_verify = HmacSha256::new_from_slice(&sr).unwrap();

        // 模拟 TCP 管道
        let (tcp_client, tcp_server) = tokio::io::duplex(64 * 1024);
        let (tcp_server_read, _tcp_server_write) = tokio::io::split(tcp_server);

        // 写入方: user → write_loop → tcp_client
        let write_handle = tokio::spawn(async move {
            let (mut user_write, user_read) = tokio::io::duplex(4096);
            let user_read_half = tokio::io::split(user_read).0;

            let wl =
                tokio::spawn(
                    async move { write_loop(user_read_half, tcp_client, hmac_write).await },
                );

            user_write.write_all(b"hello shadow").await.unwrap();
            drop(user_write);

            wl.await.unwrap().unwrap();
        });

        // 读取方: tcp_server → read_loop → user
        let read_handle = tokio::spawn(async move {
            let (user_stream, proxy_write) = tokio::io::duplex(4096);
            let proxy_write_half = tokio::io::split(proxy_write).1;

            let rl = tokio::spawn(async move {
                read_loop(tcp_server_read, proxy_write_half, hmac_read, hmac_verify).await
            });

            let mut user_stream = user_stream;
            let mut result = Vec::new();
            user_stream.read_to_end(&mut result).await.unwrap();

            let _ = rl.await;
            result
        });

        write_handle.await.unwrap();
        let result = read_handle.await.unwrap();
        assert_eq!(result, b"hello shadow");
    }
}
