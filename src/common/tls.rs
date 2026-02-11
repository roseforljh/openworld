use std::sync::Arc;

use anyhow::Result;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::CertificateDer;
use rustls::ClientConfig;

/// 跳过证书验证的 verifier（仅用于 allow_insecure=true）
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// 构建 TLS ClientConfig
///
/// - `allow_insecure`: 跳过证书验证
/// - `alpn`: 可选的 ALPN 协议列表（如 `["h2", "http/1.1"]`）
pub fn build_tls_config(allow_insecure: bool, alpn: Option<&[&str]>) -> Result<ClientConfig> {
    let provider = Arc::new(ring_provider::default_provider());
    let mut config = if allow_insecure {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    Ok(config)
}

/// 构建 TLS ClientConfig，接受自定义根证书（供测试使用）
pub fn build_tls_config_with_roots(
    roots: Vec<CertificateDer<'static>>,
    alpn: Option<&[&str]>,
) -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in roots {
        root_store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("add custom root cert failed: {}", e))?;
    }

    let provider = Arc::new(ring_provider::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    Ok(config)
}
