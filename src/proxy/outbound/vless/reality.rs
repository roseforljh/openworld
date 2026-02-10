use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{
    self, ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, NamedGroup, SignatureScheme};
use sha2::Sha256;
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha512 = Hmac<sha2::Sha512>;

tokio::task_local! {
    static REALITY_PRECOMPUTED: Arc<RealityPrecomputed>;
}

static REALITY_SECURE_RANDOM: RealitySecureRandom = RealitySecureRandom;
static REALITY_KX_GROUP: RealityKxGroup = RealityKxGroup;

/// Reality 配置
#[derive(Clone, Debug)]
pub struct RealityConfig {
    pub server_public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub server_name: String,
}

/// 预计算的 Reality 连接状态（按连接隔离）
struct RealityPrecomputed {
    random: [u8; 32],
    session_id: [u8; 32],
    ecdhe_secret: StaticSecret,
    ecdhe_public: PublicKey,
    auth_key: [u8; 32],
    random_calls: AtomicUsize,
}

/// Reality 握手上下文。
///
/// 需要在 TLS 握手 future 外层使用 `scope()` 包裹，确保自定义随机源和 KX 组
/// 能拿到本连接的 task-local 预计算状态。
pub struct RealityHandshakeContext {
    state: Arc<RealityPrecomputed>,
}

impl RealityHandshakeContext {
    pub async fn scope<F, Fut>(self, make_future: F) -> Fut::Output
    where
        F: FnOnce() -> Fut,
        Fut: Future,
    {
        REALITY_PRECOMPUTED
            .scope(self.state, async move { make_future().await })
            .await
    }
}

/// 构建 Reality TLS ClientConfig 与握手上下文。
///
/// 每次连接都需要调用此函数，因为 random / session_id / ECDHE 密钥对每次都不同。
pub fn build_reality_config(config: &RealityConfig) -> Result<(ClientConfig, RealityHandshakeContext)> {
    build_reality_config_with_roots(config, None)
}

pub fn build_reality_config_with_roots(
    config: &RealityConfig,
    extra_roots: Option<Vec<CertificateDer<'static>>>,
) -> Result<(ClientConfig, RealityHandshakeContext)> {
    // 1. 预生成 ECDHE 密钥对
    let ecdhe_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let ecdhe_public = PublicKey::from(&ecdhe_secret);

    // 2. 预生成 ClientHello.random
    let mut random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);

    // 3. 用 ECDHE 私钥 + 服务端公钥做 ECDH
    let server_public = PublicKey::from(config.server_public_key);
    let shared_secret = ecdhe_secret.diffie_hellman(&server_public);

    // 4. HKDF 派生 AuthKey
    //    Salt: random[0:20], IKM: shared_secret, Info: "REALITY"
    let hkdf = Hkdf::<Sha256>::new(Some(&random[..20]), shared_secret.as_bytes());
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;

    // 5. 构造 SessionId 明文
    //    [0]: 版本号, [1-3]: 保留, [4-7]: 时间戳, [8-15]: short_id, [16-31]: 零
    let mut session_id = [0u8; 32];
    session_id[0] = 1; // Reality 版本
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    session_id[4..8].copy_from_slice(&timestamp.to_be_bytes());
    let sid_len = config.short_id.len().min(8);
    session_id[8..8 + sid_len].copy_from_slice(&config.short_id[..sid_len]);

    // 6. AES-128-GCM 加密 SessionId[0:16]
    //    Key: auth_key[0:16], Nonce: random[20:32], AAD: 无（简化）
    //    输出: 16 字节密文 + 16 字节 tag = 32 字节，覆盖整个 session_id
    let aead = Aes128Gcm::new_from_slice(&auth_key[..16])
        .map_err(|e| anyhow::anyhow!("AES-GCM key init failed: {}", e))?;
    let nonce = Nonce::from_slice(&random[20..32]);
    let ciphertext = aead
        .encrypt(nonce, &session_id[..16])
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {}", e))?;
    session_id.copy_from_slice(&ciphertext);

    debug!("Reality: session_id encrypted, auth_key derived");

    // 7. 构建 task-local 连接状态（替代每连接 Box::leak）
    let state = Arc::new(RealityPrecomputed {
        random,
        session_id,
        ecdhe_secret,
        ecdhe_public,
        auth_key,
        random_calls: AtomicUsize::new(0),
    });

    // 8. 构建自定义 CryptoProvider
    let ring_provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(CryptoProvider {
        cipher_suites: ring_provider.cipher_suites,
        kx_groups: vec![&REALITY_KX_GROUP],
        signature_verification_algorithms: ring_provider.signature_verification_algorithms,
        secure_random: &REALITY_SECURE_RANDOM,
        key_provider: ring_provider.key_provider,
    });

    // 9. 构建标准 X.509 回退验证器
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(extra) = extra_roots {
        for cert in extra {
            root_store
                .add(cert)
                .map_err(|e| anyhow::anyhow!("add extra root failed: {}", e))?;
        }
    }
    let fallback_verifier: Arc<dyn ServerCertVerifier> =
        WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("build webpki verifier failed: {}", e))?;

    // 10. 构建 ClientConfig
    let tls_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RealityVerifier {
            auth_key: state.auth_key,
            server_name: config.server_name.clone(),
            fallback: fallback_verifier,
            supported_algorithms: provider.signature_verification_algorithms,
        }))
        .with_no_client_auth();

    Ok((tls_config, RealityHandshakeContext { state }))
}

/// 自定义 SecureRandom -- 从 task-local 状态注入预计算 random 和 session_id
#[derive(Debug)]
struct RealitySecureRandom;

impl SecureRandom for RealitySecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let injected = REALITY_PRECOMPUTED
            .try_with(|state| {
                let call = state.random_calls.fetch_add(1, Ordering::SeqCst);
                match (call, buf.len()) {
                    // 第 1 次 32 字节调用: session_id
                    (0, 32) => {
                        buf.copy_from_slice(&state.session_id);
                        true
                    }
                    // 第 2 次 32 字节调用: random
                    (1, 32) => {
                        buf.copy_from_slice(&state.random);
                        true
                    }
                    _ => false,
                }
            })
            .unwrap_or(false);

        if injected {
            return Ok(());
        }

        // 其他调用使用系统随机
        use rand::RngCore;
        rand::thread_rng()
            .try_fill_bytes(buf)
            .map_err(|_| GetRandomFailed)
    }
}

/// 自定义密钥交换组 -- 使用 task-local 预生成的 x25519 密钥对
#[derive(Debug)]
struct RealityKxGroup;

impl SupportedKxGroup for RealityKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        REALITY_PRECOMPUTED
            .try_with(|state| {
                Box::new(RealityKeyExchange {
                    private_key: state.ecdhe_secret.clone(),
                    public_key: state.ecdhe_public,
                }) as Box<dyn ActiveKeyExchange>
            })
            .map_err(|_| rustls::Error::General("Reality task-local state not set".into()))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// 自定义密钥交换 -- 使用预生成的 x25519 密钥对完成 ECDH
struct RealityKeyExchange {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl ActiveKeyExchange for RealityKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_bytes: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let peer_public = PublicKey::from(peer_bytes);
        let shared = self.private_key.diffie_hellman(&peer_public);
        Ok(SharedSecret::from(shared.as_bytes() as &[u8]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl Debug for RealityKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityKeyExchange").finish()
    }
}

/// Reality 证书验证器
///
/// 验证逻辑：
/// 1. 尝试 Reality HMAC 验证（通过则立即信任）
/// 2. HMAC 不通过或无法解析时，回退到标准 X.509 验证
#[derive(Debug)]
struct RealityVerifier {
    auth_key: [u8; 32],
    server_name: String,
    fallback: Arc<dyn ServerCertVerifier>,
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert_der = end_entity.as_ref();

        debug!(
            "Reality: verifying server cert ({} bytes), expected_server_name={}, actual_server_name={:?}",
            cert_der.len(),
            self.server_name,
            server_name
        );

        // 优先尝试 Reality HMAC 验证
        if self.try_verify_reality_cert(cert_der).unwrap_or(false) {
            debug!("Reality: server cert verified via HMAC");
            return Ok(ServerCertVerified::assertion());
        }

        // 回退标准 X.509 验证
        debug!("Reality: HMAC verification not matched, fallback to WebPKI verification");
        self.fallback
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.fallback.root_hint_subjects()
    }
}

impl RealityVerifier {
    /// 尝试验证 Reality 证书。
    /// 返回 Some(true) 如果 HMAC 验证通过，Some(false) 如果不通过，None 如果解析失败。
    fn try_verify_reality_cert(&self, cert_der: &[u8]) -> Option<bool> {
        let pub_key = Self::extract_ed25519_public_key(cert_der)?;
        let cert_signature = Self::extract_certificate_signature(cert_der)?;

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&self.auth_key).ok()?;
        mac.update(&pub_key);
        let expected_sig = mac.finalize().into_bytes();

        Some(cert_signature == expected_sig.as_slice())
    }

    /// 从证书中提取 ed25519 公钥（32 字节）。
    fn extract_ed25519_public_key(cert_der: &[u8]) -> Option<[u8; 32]> {
        // ed25519 OID: 1.3.101.112 = 06 03 2b 65 70
        let ed25519_oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let oid_pos = cert_der
            .windows(ed25519_oid.len())
            .position(|w| w == ed25519_oid)?;

        // 查找紧随 OID 后的 BIT STRING: 03 21 00 <32-byte-key>
        let search_start = oid_pos + ed25519_oid.len();
        let max_start = cert_der.len().saturating_sub(35);
        for pos in search_start..=max_start {
            if cert_der[pos] == 0x03 && cert_der[pos + 1] == 0x21 && cert_der[pos + 2] == 0x00 {
                let mut pub_key = [0u8; 32];
                pub_key.copy_from_slice(&cert_der[pos + 3..pos + 35]);
                return Some(pub_key);
            }
        }

        None
    }

    /// 从 X.509 Certificate DER 提取最外层 signatureValue BIT STRING。
    /// 返回去掉首字节 unused-bits 标记后的签名字节。
    fn extract_certificate_signature(cert_der: &[u8]) -> Option<&[u8]> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
        let (outer_tag, outer_value_start, _outer_len, outer_end) =
            Self::parse_der_tlv(cert_der, 0)?;
        if outer_tag != 0x30 || outer_end != cert_der.len() {
            return None;
        }

        let (_, _, _, first_end) = Self::parse_der_tlv(cert_der, outer_value_start)?;
        let (_, _, _, second_end) = Self::parse_der_tlv(cert_der, first_end)?;
        let (sig_tag, sig_value_start, sig_len, sig_end) = Self::parse_der_tlv(cert_der, second_end)?;

        if sig_tag != 0x03 || sig_end != outer_end || sig_len < 1 {
            return None;
        }

        let unused_bits = cert_der[sig_value_start];
        if unused_bits != 0 {
            return None;
        }

        Some(&cert_der[sig_value_start + 1..sig_value_start + sig_len])
    }

    /// 解析 DER TLV，返回 (tag, value_start, value_len, next_offset)
    fn parse_der_tlv(data: &[u8], offset: usize) -> Option<(u8, usize, usize, usize)> {
        let tag = *data.get(offset)?;
        let mut cursor = offset + 1;

        let len_first = *data.get(cursor)?;
        cursor += 1;

        let value_len = if (len_first & 0x80) == 0 {
            len_first as usize
        } else {
            let len_octets = (len_first & 0x7f) as usize;
            if len_octets == 0 || len_octets > std::mem::size_of::<usize>() {
                return None;
            }
            if cursor + len_octets > data.len() {
                return None;
            }

            let mut len = 0usize;
            for &b in &data[cursor..cursor + len_octets] {
                len = len.checked_mul(256)?.checked_add(b as usize)?;
            }
            cursor += len_octets;
            len
        };

        let value_start = cursor;
        let value_end = value_start.checked_add(value_len)?;
        if value_end > data.len() {
            return None;
        }

        Some((tag, value_start, value_len, value_end))
    }
}

/// 解析 hex 字符串为字节数组
pub fn parse_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("invalid hex string length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))
        })
        .collect()
}

/// 解析 base64 编码的公钥
pub fn parse_public_key(key_str: &str) -> Result<[u8; 32]> {
    // 尝试 base64 标准编码
    let bytes = base64_decode(key_str)?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "invalid public key length: expected 32, got {}",
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// 简单的 base64 解码（不引入额外依赖）
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 也支持 URL-safe base64
    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'\n' | b'\r' | b' ' => continue,
            _ => anyhow::bail!("invalid base64 character: {}", byte as char),
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    let _ = TABLE; // 保留常量，便于后续替换为查表实现
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0a1b2c").unwrap(), vec![0x0a, 0x1b, 0x2c]);
        assert_eq!(parse_hex("").unwrap(), vec![]);
        assert!(parse_hex("0g").is_err());
        assert!(parse_hex("0").is_err());
    }

    #[test]
    fn test_base64_decode() {
        // "hello" in base64 = "aGVsbG8="
        let decoded = base64_decode("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");

        // URL-safe base64
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_parse_public_key() {
        // 32 bytes of zeros in base64
        let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = parse_public_key(key_b64).unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn test_auth_key_derivation() {
        // 验证 HKDF 派生 AuthKey 的基本流程
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let shared = secret.diffie_hellman(&server_public);
        let random = [0x42u8; 32];

        let hkdf = Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key).unwrap();

        // AuthKey 应该是确定性的
        let hkdf2 = Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes());
        let mut auth_key2 = [0u8; 32];
        hkdf2.expand(b"REALITY", &mut auth_key2).unwrap();
        assert_eq!(auth_key, auth_key2);
    }

    #[test]
    fn test_session_id_encryption() {
        let auth_key = [0x42u8; 32];
        let random = [0x55u8; 32];

        let mut session_id = [0u8; 32];
        session_id[0] = 1;
        session_id[4..8].copy_from_slice(&1234u32.to_be_bytes());
        session_id[8..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // 加密
        let aead = Aes128Gcm::new_from_slice(&auth_key[..16]).unwrap();
        let nonce = Nonce::from_slice(&random[20..32]);
        let ciphertext = aead.encrypt(nonce, &session_id[..16]).unwrap();
        assert_eq!(ciphertext.len(), 32); // 16 plaintext + 16 tag

        // 解密验证
        let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(plaintext[0], 1); // 版本号
        assert_eq!(&plaintext[4..8], &1234u32.to_be_bytes());
    }

    #[test]
    fn test_hmac_sha512() {
        let auth_key = [0x42u8; 32];
        let pub_key = [0x55u8; 32];

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&auth_key).unwrap();
        mac.update(&pub_key);
        let result = mac.finalize().into_bytes();
        assert_eq!(result.len(), 64);

        // 验证确定性
        let mut mac2 = <HmacSha512 as Mac>::new_from_slice(&auth_key).unwrap();
        mac2.update(&pub_key);
        let result2 = mac2.finalize().into_bytes();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_build_reality_config() {
        let config = RealityConfig {
            server_public_key: [0x42u8; 32],
            short_id: vec![0xAA, 0xBB, 0xCC, 0xDD],
            server_name: "www.example.com".to_string(),
        };

        let result = build_reality_config(&config);
        assert!(result.is_ok());
        let (tls_config, _ctx) = result.unwrap();
        assert!(tls_config.alpn_protocols.is_empty()); // 默认无 ALPN
    }

    fn build_synthetic_reality_cert(pub_key: [u8; 32], sig: [u8; 64]) -> Vec<u8> {
        // tbsCertificate (伪造，只需包含 ed25519 OID + BIT STRING 公钥模式)
        let mut tbs_content = vec![0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        tbs_content.extend_from_slice(&pub_key);
        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);

        // signatureAlgorithm (伪造)
        let sig_alg = vec![0x30, 0x03, 0x06, 0x01, 0x2a];

        // signatureValue BIT STRING
        let mut sig_value = vec![0x00];
        sig_value.extend_from_slice(&sig);
        let mut sig_bit_string = vec![0x03, sig_value.len() as u8];
        sig_bit_string.extend_from_slice(&sig_value);

        // 外层 Certificate SEQUENCE
        let total_len = tbs.len() + sig_alg.len() + sig_bit_string.len();
        let mut cert = vec![0x30, total_len as u8];
        cert.extend_from_slice(&tbs);
        cert.extend_from_slice(&sig_alg);
        cert.extend_from_slice(&sig_bit_string);
        cert
    }

    fn make_test_verifier(auth_key: [u8; 32]) -> RealityVerifier {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let fallback: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap();

        RealityVerifier {
            auth_key,
            server_name: "example.com".to_string(),
            fallback,
            supported_algorithms: provider.signature_verification_algorithms,
        }
    }

    fn issue_ed25519_ca_and_server(
        server_name: &str,
    ) -> (
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
        CertificateDer<'static>,
        [u8; 32],
    ) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OpenWorld Reality Test CA");

        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut server_params = CertificateParams::new(vec![server_name.to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, server_name);
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        let server_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let ca_der = CertificateDer::from(ca_cert.der().to_vec());
        let chain = vec![CertificateDer::from(server_cert.der().to_vec()), ca_der.clone()];
        let key = rustls::pki_types::PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            server_key.serialize_der(),
        ));

        let server_pub = RealityVerifier::extract_ed25519_public_key(server_cert.der().as_ref())
            .expect("ed25519 public key must exist");

        (chain, key, ca_der, server_pub)
    }

    #[tokio::test]
    async fn test_reality_fallback_x509_roundtrip() {
        let server_name = "reality-test.local";
        let (cert_chain, server_key, ca_root, _) = issue_ed25519_ca_and_server(server_name);

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(cert_chain, server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();

            let mut req = [0u8; 4];
            tls.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"ping");

            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let server_pub = PublicKey::from(&StaticSecret::random_from_rng(rand::thread_rng()));
        let cfg = RealityConfig {
            server_public_key: *server_pub.as_bytes(),
            short_id: vec![0x11, 0x22, 0x33, 0x44],
            server_name: server_name.to_string(),
        };

        let (client_cfg, handshake_ctx) =
            build_reality_config_with_roots(&cfg, Some(vec![ca_root])).unwrap();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(listen_addr).await.unwrap();
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let mut tls = handshake_ctx
            .scope(|| connector.connect(name, tcp))
            .await
            .unwrap();

        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();

        let mut resp = [0u8; 4];
        tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");

        server_task.await.unwrap();
    }

    #[test]
    fn test_reality_hmac_path_bypasses_invalid_x509() {
        let auth_key = [0x5Au8; 32];
        let server_pub = [0x11u8; 32];

        let mut hmac = <HmacSha512 as Mac>::new_from_slice(&auth_key).unwrap();
        hmac.update(&server_pub);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&hmac.finalize().into_bytes());

        let cert = CertificateDer::from(build_synthetic_reality_cert(server_pub, sig));

        // 构造仅系统根的 fallback。对于 synthetic cert，若走 X509 路径会失败。
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let fallback: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap();

        let reality_verifier = RealityVerifier {
            auth_key,
            server_name: "reality-hmac.local".to_string(),
            fallback,
            supported_algorithms: provider.signature_verification_algorithms,
        };

        let result = reality_verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("reality-hmac.local".to_string()).unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(
            result.is_ok(),
            "HMAC path should accept cert even when fallback X509 would fail"
        );
    }

    #[test]
    fn test_reality_rejects_when_hmac_miss_and_x509_invalid() {
        let auth_key = [0x5Au8; 32];
        let server_pub = [0x11u8; 32];
        let sig = [0x22u8; 64];

        let cert = CertificateDer::from(build_synthetic_reality_cert(server_pub, sig));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let fallback: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap();

        let reality_verifier = RealityVerifier {
            auth_key,
            server_name: "reality-reject.local".to_string(),
            fallback,
            supported_algorithms: provider.signature_verification_algorithms,
        };

        let result = reality_verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("reality-reject.local".to_string()).unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(
            result.is_err(),
            "when HMAC mismatches and X509 is invalid, verification must fail"
        );
    }

    #[test]
    fn test_try_verify_reality_cert_success() {
        let auth_key = [0x33u8; 32];
        let pub_key = [0x55u8; 32];

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&auth_key).unwrap();
        mac.update(&pub_key);
        let expected = mac.finalize().into_bytes();

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&expected);

        let cert = build_synthetic_reality_cert(pub_key, sig);
        let verifier = make_test_verifier(auth_key);
        assert_eq!(verifier.try_verify_reality_cert(&cert), Some(true));
    }

    #[test]
    fn test_try_verify_reality_cert_mismatch() {
        let auth_key = [0x33u8; 32];
        let pub_key = [0x55u8; 32];

        let mut sig = [0xAAu8; 64];
        sig[0] = 0xAB;

        let cert = build_synthetic_reality_cert(pub_key, sig);
        let verifier = make_test_verifier(auth_key);
        assert_eq!(verifier.try_verify_reality_cert(&cert), Some(false));
    }

    #[test]
    fn test_extract_certificate_signature_reject_unused_bits() {
        let pub_key = [0x55u8; 32];
        let sig = [0x11u8; 64];
        let mut cert = build_synthetic_reality_cert(pub_key, sig);

        // signatureValue BIT STRING 的第一个内容字节是 unused bits，改成 1 应被拒绝
        // 定位最后一个 BIT STRING 头（03 41）后一个字节
        let pos = cert
            .windows(2)
            .rposition(|w| w == [0x03, 0x41])
            .unwrap();
        cert[pos + 2] = 0x01;

        assert!(RealityVerifier::extract_certificate_signature(&cert).is_none());
    }
}
