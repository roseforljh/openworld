/// TLS ClientHello fingerprint mimicry system.
///
/// Configures rustls `ClientConfig` to approximate the TLS fingerprint of
/// popular browsers (Chrome, Firefox, Safari, Edge, iOS, Android, etc.).
///
/// This works by selecting cipher suites, protocol versions, and ALPN
/// protocols that match the target browser's known JA3/JA4 fingerprint.
use std::sync::Arc;

use anyhow::Result;
use rustls::crypto::ring as ring_provider;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, SupportedCipherSuite};
use tracing::debug;

/// Known browser fingerprint profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintType {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Ios,
    Android,
    Random,
    /// Use rustls defaults (no fingerprint mimicry)
    None,
}

impl FingerprintType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "edge" => Self::Edge,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "random" | "randomized" => Self::Random,
            _ => Self::None,
        }
    }
}

/// Cipher suite ordering for Chrome/Edge (Chromium-based)
/// JA3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
///      ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, ...
fn chrome_cipher_suites() -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;
    vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Cipher suite ordering for Firefox
/// Firefox prefers ChaCha20 over AES-GCM on non-AES-NI hardware
fn firefox_cipher_suites() -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;
    vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]
}

/// Cipher suite ordering for Safari / iOS
/// Safari uses a similar ordering to Chrome but with slight differences
fn safari_cipher_suites() -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;
    vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// ALPN protocols for different browsers
fn browser_alpn(fp: FingerprintType) -> Vec<Vec<u8>> {
    match fp {
        FingerprintType::Chrome | FingerprintType::Edge | FingerprintType::Android => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        FingerprintType::Firefox => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        FingerprintType::Safari | FingerprintType::Ios => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    }
}

/// Select a random fingerprint type
fn random_fingerprint() -> FingerprintType {
    use rand::Rng;
    let choices = [
        FingerprintType::Chrome,
        FingerprintType::Firefox,
        FingerprintType::Safari,
        FingerprintType::Edge,
    ];
    let idx = rand::thread_rng().gen_range(0..choices.len());
    choices[idx]
}

/// Build a CryptoProvider with cipher suites ordered to match the target fingerprint
fn build_fingerprinted_provider(fp: FingerprintType) -> CryptoProvider {
    let effective_fp = match fp {
        FingerprintType::Random => random_fingerprint(),
        other => other,
    };

    let cipher_suites = match effective_fp {
        FingerprintType::Chrome | FingerprintType::Edge | FingerprintType::Android => {
            chrome_cipher_suites()
        }
        FingerprintType::Firefox => firefox_cipher_suites(),
        FingerprintType::Safari | FingerprintType::Ios => safari_cipher_suites(),
        _ => ring_provider::default_provider().cipher_suites,
    };

    let default = ring_provider::default_provider();
    CryptoProvider {
        cipher_suites,
        kx_groups: default.kx_groups,
        signature_verification_algorithms: default.signature_verification_algorithms,
        secure_random: default.secure_random,
        key_provider: default.key_provider,
    }
}

/// Build a TLS `ClientConfig` with browser fingerprint mimicry.
///
/// This configures cipher suite ordering, ALPN, and protocol versions
/// to approximate the JA3/JA4 fingerprint of the target browser.
pub fn build_fingerprinted_tls_config(
    fingerprint: FingerprintType,
    allow_insecure: bool,
    alpn_override: Option<&[&str]>,
) -> Result<ClientConfig> {
    if fingerprint == FingerprintType::None {
        return crate::common::tls::build_tls_config(allow_insecure, alpn_override);
    }

    let provider = Arc::new(build_fingerprinted_provider(fingerprint));

    let mut config = if allow_insecure {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::common::tls::NoVerifier))
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

    // Set ALPN: use override if provided, otherwise use browser-specific defaults
    if let Some(protocols) = alpn_override {
        config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    } else {
        config.alpn_protocols = browser_alpn(fingerprint);
    }

    debug!(fingerprint = ?fingerprint, "built fingerprinted TLS config");
    Ok(config)
}

/// Build a fingerprinted TLS config with custom root certificates (for testing)
pub fn build_fingerprinted_tls_config_with_roots(
    fingerprint: FingerprintType,
    roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    alpn_override: Option<&[&str]>,
) -> Result<ClientConfig> {
    if fingerprint == FingerprintType::None {
        return crate::common::tls::build_tls_config_with_roots(roots, alpn_override);
    }

    let provider = Arc::new(build_fingerprinted_provider(fingerprint));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in roots {
        root_store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("add custom root cert failed: {}", e))?;
    }

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if let Some(protocols) = alpn_override {
        config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    } else {
        config.alpn_protocols = browser_alpn(fingerprint);
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_type_from_str() {
        assert_eq!(FingerprintType::from_str("chrome"), FingerprintType::Chrome);
        assert_eq!(FingerprintType::from_str("Chrome"), FingerprintType::Chrome);
        assert_eq!(
            FingerprintType::from_str("firefox"),
            FingerprintType::Firefox
        );
        assert_eq!(FingerprintType::from_str("safari"), FingerprintType::Safari);
        assert_eq!(FingerprintType::from_str("edge"), FingerprintType::Edge);
        assert_eq!(FingerprintType::from_str("ios"), FingerprintType::Ios);
        assert_eq!(
            FingerprintType::from_str("android"),
            FingerprintType::Android
        );
        assert_eq!(FingerprintType::from_str("random"), FingerprintType::Random);
        assert_eq!(
            FingerprintType::from_str("unknown"),
            FingerprintType::None
        );
    }

    #[test]
    fn test_chrome_cipher_suites_order() {
        let suites = chrome_cipher_suites();
        assert_eq!(suites.len(), 9);
        // TLS 1.3 suites first
        assert!(format!("{:?}", suites[0]).contains("TLS13_AES_128_GCM"));
        assert!(format!("{:?}", suites[1]).contains("TLS13_AES_256_GCM"));
        assert!(format!("{:?}", suites[2]).contains("TLS13_CHACHA20"));
    }

    #[test]
    fn test_firefox_cipher_suites_order() {
        let suites = firefox_cipher_suites();
        assert_eq!(suites.len(), 9);
        // Firefox: AES-128-GCM first, then ChaCha20, then AES-256-GCM
        assert!(format!("{:?}", suites[0]).contains("TLS13_AES_128_GCM"));
        assert!(format!("{:?}", suites[1]).contains("TLS13_CHACHA20"));
        assert!(format!("{:?}", suites[2]).contains("TLS13_AES_256_GCM"));
    }

    #[test]
    fn test_build_fingerprinted_config_chrome() {
        let config =
            build_fingerprinted_tls_config(FingerprintType::Chrome, false, None).unwrap();
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_build_fingerprinted_config_firefox() {
        let config =
            build_fingerprinted_tls_config(FingerprintType::Firefox, false, None).unwrap();
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_build_fingerprinted_config_none_fallback() {
        let config = build_fingerprinted_tls_config(FingerprintType::None, false, None).unwrap();
        // None fingerprint uses default rustls config (no ALPN by default)
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn test_build_fingerprinted_config_with_alpn_override() {
        let config = build_fingerprinted_tls_config(
            FingerprintType::Chrome,
            false,
            Some(&["h2"]),
        )
        .unwrap();
        assert_eq!(config.alpn_protocols.len(), 1);
        assert_eq!(config.alpn_protocols[0], b"h2");
    }

    #[test]
    fn test_build_fingerprinted_config_insecure() {
        let config =
            build_fingerprinted_tls_config(FingerprintType::Safari, true, None).unwrap();
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_random_fingerprint_is_valid() {
        let fp = random_fingerprint();
        assert!(matches!(
            fp,
            FingerprintType::Chrome
                | FingerprintType::Firefox
                | FingerprintType::Safari
                | FingerprintType::Edge
        ));
    }

    #[test]
    fn test_build_fingerprinted_config_random() {
        // Random should succeed and produce a valid config
        let config =
            build_fingerprinted_tls_config(FingerprintType::Random, false, None).unwrap();
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_provider_cipher_suite_count() {
        let provider = build_fingerprinted_provider(FingerprintType::Chrome);
        assert_eq!(provider.cipher_suites.len(), 9);

        let provider = build_fingerprinted_provider(FingerprintType::Firefox);
        assert_eq!(provider.cipher_suites.len(), 9);

        let provider = build_fingerprinted_provider(FingerprintType::Safari);
        assert_eq!(provider.cipher_suites.len(), 9);
    }
}
