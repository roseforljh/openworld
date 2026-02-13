// MASQUE 出站 — ECDSA TLS 配置
//
// 兼容 Cloudflare WARP MASQUE 端点：
// - ECDSA P-256 密钥对
// - 自签名证书
// - 公钥固定验证（替代 CA 链验证）

use std::sync::Arc;

use anyhow::Result;

/// 准备 MASQUE TLS 配置
///
/// 生成自签名证书，使用 ECDSA 私钥进行客户端认证，
/// 并通过公钥固定验证服务端证书。
pub fn prepare_tls_config(
    private_key_pem: &str,
    peer_public_key_der: &[u8],
    _sni: &str,
) -> Result<rustls::ClientConfig> {
    // 1. 生成自签名证书
    let (cert_chain, rustls_key) = generate_self_signed_cert(private_key_pem)?;

    // 2. 构建 crypto provider
    let provider = rustls::crypto::ring::default_provider();

    // 3. 构建客户端配置
    //    - InsecureSkipVerify: SNI 通常不是端点域名，跳过 CA 验证
    //    - 公钥固定验证通过自定义 verifier 实现
    let peer_pub = peer_public_key_der.to_vec();
    let verifier = Arc::new(PinnedKeyVerifier {
        peer_public_key: peer_pub,
    });

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, rustls_key)?;

    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;

    Ok(config)
}

/// 生成 ECDSA 自签名证书
fn generate_self_signed_cert(
    private_key_pem: &str,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::from_pem(private_key_pem)?;
    let key_der = key_pair.serialize_der();

    let params = CertificateParams::new(vec![])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let private_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );

    Ok((vec![cert_der], private_key_der))
}

/// 公钥固定验证器
///
/// 不验证 CA 链，只验证服务端证书的公钥是否匹配期望的公钥。
/// 这是 Cloudflare WARP MASQUE 端点的认证方式。
#[derive(Debug)]
struct PinnedKeyVerifier {
    peer_public_key: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 简单比较：从证书 DER 中查找公钥字节序列
        // 这比完整的 X.509 ASN.1 解析更轻量
        let cert_der = end_entity.as_ref();

        // 如果 peer_public_key 为空，跳过验证（信任所有）
        if self.peer_public_key.is_empty() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // 检查证书是否包含期望的公钥字节
        if contains_subsequence(cert_der, &self.peer_public_key) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Server public key does not match pinned key",
                )))),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        ]
    }
}

/// 在 haystack 中搜索 needle 子序列
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// 解析 Base64 编码的 DER 数据
pub fn decode_base64(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64: {}", e))?;
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64() {
        use base64::Engine;
        let data = vec![1u8, 2, 3, 4, 5];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let decoded = decode_base64(&b64).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_contains_subsequence() {
        assert!(contains_subsequence(b"hello world", b"world"));
        assert!(!contains_subsequence(b"hello", b"world"));
        assert!(contains_subsequence(b"abc", b""));
    }
}
