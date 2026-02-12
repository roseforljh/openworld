/// kTLS — 内核层 TLS 加密卸载（Linux 4.13+）。
///
/// 当 TLS 握手完成后，可以将密钥材料传递给内核，
/// 让内核在 TCP 层面直接执行 AES-GCM 加解密，
/// 从而实现 sendfile() 零拷贝和减少上下文切换。
///
/// ## 使用流程
/// 1. 完成 TLS 握手（用户态 rustls/openssl）
/// 2. 提取协商的密钥材料（cipher_suite, key, iv, seq）
/// 3. 调用 `enable_ktls()` 将密钥设置到内核
/// 4. 后续数据读写自动由内核加解密
///
/// ## 要求
/// - Linux 内核 4.13+ (kTLS 基础)
/// - Linux 内核 4.17+ (接收端 kTLS)
/// - `CONFIG_TLS=y` 编译选项开启
/// - 支持的加密套件: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305

use anyhow::Result;
use tracing::debug;

/// kTLS 加密套件标识
#[derive(Debug, Clone, Copy)]
pub enum KtlsCipher {
    /// AES-128-GCM (TLS 1.2/1.3)
    Aes128Gcm,
    /// AES-256-GCM (TLS 1.2/1.3)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (TLS 1.3, Linux 5.11+)
    Chacha20Poly1305,
}

/// kTLS 密钥材料
#[derive(Debug)]
pub struct KtlsCryptoInfo {
    /// TLS 版本 (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
    pub tls_version: u16,
    /// 加密套件
    pub cipher: KtlsCipher,
    /// 加密密钥
    pub key: Vec<u8>,
    /// 初始向量 (IV)
    pub iv: Vec<u8>,
    /// 序列号
    pub seq: [u8; 8],
    /// 额外的 salt/implicit nonce
    pub salt: Vec<u8>,
}

/// 尝试为已完成 TLS 握手的 TCP socket 启用 kTLS。
///
/// 返回 `Ok(true)` 表示成功启用 kTLS。
/// 返回 `Ok(false)` 表示当前平台/内核不支持。
/// 返回 `Err` 表示尝试设置时出错。
pub fn enable_ktls(
    #[allow(unused_variables)] fd: std::os::raw::c_int,
    #[allow(unused_variables)] tx_info: &KtlsCryptoInfo,
    #[allow(unused_variables)] rx_info: Option<&KtlsCryptoInfo>,
) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        enable_ktls_linux(fd, tx_info, rx_info)
    }

    #[cfg(not(target_os = "linux"))]
    {
        debug!("kTLS is only supported on Linux 4.13+");
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn enable_ktls_linux(
    fd: std::os::raw::c_int,
    tx_info: &KtlsCryptoInfo,
    rx_info: Option<&KtlsCryptoInfo>,
) -> Result<bool> {
    use std::mem;

    // Linux kTLS 常量
    const SOL_TLS: i32 = 282;
    const TLS_TX: i32 = 1;
    const TLS_RX: i32 = 2;
    const TLS_1_2_VERSION: u16 = 0x0303;
    const TLS_1_3_VERSION: u16 = 0x0304;
    const TLS_CIPHER_AES_GCM_128: u16 = 51;
    const TLS_CIPHER_AES_GCM_256: u16 = 52;
    const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

    // 1. 设置 SOL_TLS 协议到 socket
    let proto: i32 = SOL_TLS;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_ULP,
            &proto as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            debug!("kTLS not available: kernel module not loaded");
            return Ok(false);
        }
        debug!(error = %err, "kTLS ULP setup failed");
        return Ok(false);
    }

    // 2. 设置 TX 密钥
    set_ktls_key(fd, TLS_TX, tx_info, TLS_1_2_VERSION, TLS_1_3_VERSION,
        TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256, TLS_CIPHER_CHACHA20_POLY1305)?;

    // 3. 设置 RX 密钥 (可选)
    if let Some(rx) = rx_info {
        set_ktls_key(fd, TLS_RX, rx, TLS_1_2_VERSION, TLS_1_3_VERSION,
            TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256, TLS_CIPHER_CHACHA20_POLY1305)?;
    }

    debug!(cipher = ?tx_info.cipher, "kTLS enabled successfully");
    Ok(true)
}

/// 设置单方向（TX 或 RX）的 kTLS 密钥
#[cfg(target_os = "linux")]
fn set_ktls_key(
    fd: std::os::raw::c_int,
    direction: i32,
    info: &KtlsCryptoInfo,
    tls_12: u16,
    tls_13: u16,
    aes128: u16,
    aes256: u16,
    chacha20: u16,
) -> Result<()> {
    const SOL_TLS: i32 = 282;

    // kTLS crypto_info 头部 (内核结构: tls_crypto_info)
    //   u16 version;
    //   u16 cipher_type;
    let version = match info.tls_version {
        0x0303 => tls_12,
        0x0304 => tls_13,
        v => anyhow::bail!("unsupported TLS version: 0x{:04x}", v),
    };

    let cipher_type = match info.cipher {
        KtlsCipher::Aes128Gcm => aes128,
        KtlsCipher::Aes256Gcm => aes256,
        KtlsCipher::Chacha20Poly1305 => chacha20,
    };

    // 构建完整的 crypto_info 结构
    // 头部 (4 bytes) + iv + key + salt + rec_seq
    let mut buf = Vec::new();
    buf.extend_from_slice(&version.to_ne_bytes());
    buf.extend_from_slice(&cipher_type.to_ne_bytes());

    // IV
    buf.extend_from_slice(&info.iv);
    // Key
    buf.extend_from_slice(&info.key);
    // Salt
    buf.extend_from_slice(&info.salt);
    // Sequence number
    buf.extend_from_slice(&info.seq);

    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            buf.as_ptr() as *const libc::c_void,
            buf.len() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("kTLS set {} key failed: {}", if direction == 1 { "TX" } else { "RX" }, err);
    }

    Ok(())
}

/// 检查当前系统是否支持 kTLS
pub fn is_ktls_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // 检查 /proc/modules 中是否加载了 tls 模块
        std::fs::read_to_string("/proc/modules")
            .map(|content| content.contains("tls "))
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ktls_availability_check() {
        // 不应 panic
        let available = is_ktls_available();
        // Windows 上一定为 false
        #[cfg(not(target_os = "linux"))]
        assert!(!available);
        let _ = available;
    }

    #[test]
    fn ktls_cipher_debug() {
        let info = KtlsCryptoInfo {
            tls_version: 0x0304,
            cipher: KtlsCipher::Aes256Gcm,
            key: vec![0; 32],
            iv: vec![0; 12],
            seq: [0; 8],
            salt: vec![0; 4],
        };
        assert!(format!("{:?}", info).contains("Aes256Gcm"));
    }

    #[test]
    fn non_linux_enable_returns_false() {
        #[cfg(not(target_os = "linux"))]
        {
            let info = KtlsCryptoInfo {
                tls_version: 0x0304,
                cipher: KtlsCipher::Aes128Gcm,
                key: vec![0; 16],
                iv: vec![0; 12],
                seq: [0; 8],
                salt: vec![0; 4],
            };
            let result = enable_ktls(0, &info, None);
            assert!(result.is_ok());
            assert!(!result.unwrap());
        }
    }
}
