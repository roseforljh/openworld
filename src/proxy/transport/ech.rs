/// Encrypted Client Hello (ECH) support.
///
/// ECH encrypts the SNI and other sensitive fields in the TLS ClientHello,
/// preventing network observers from seeing which domain the client is connecting to.
///
/// This module provides:
/// - ECH configuration from raw config bytes or DNS HTTPS records
/// - Automatic ECH config fetching from DNS HTTPS records
/// - GREASE ECH for anti-ossification when no ECH config is available
/// - Integration with the fingerprint system
use std::sync::Arc;

use anyhow::Result;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::EchConfigListBytes;
use rustls::ClientConfig;
use tracing::debug;

use super::fingerprint::{self, FingerprintType};
use crate::config::types::TlsConfig;

/// HPKE suites supported for ECH
fn supported_hpke_suites() -> &'static [&'static dyn Hpke] {
    // rustls 0.23 ECH HPKE suites are provided by aws-lc-rs backend
    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
}

/// ECH configuration for outbound connections
#[derive(Debug, Clone)]
pub struct EchSettings {
    /// Raw ECH config list bytes (from DNS HTTPS record or manual config)
    pub config_list: Option<Vec<u8>>,
    /// Whether to use GREASE ECH when no config is available
    pub grease: bool,
    /// Outer SNI to use (the public-facing server name)
    pub outer_sni: Option<String>,
}

impl Default for EchSettings {
    fn default() -> Self {
        Self {
            config_list: None,
            grease: false,
            outer_sni: None,
        }
    }
}

impl EchSettings {
    pub fn is_enabled(&self) -> bool {
        self.config_list.is_some() || self.grease
    }
}

/// Build an ECH-enabled TLS `ClientConfig`.
///
/// If `ech_config_list` is provided, real ECH is used.
/// If `grease` is true and no config is available, GREASE ECH is used.
/// Otherwise, returns a normal (non-ECH) config.
pub fn build_ech_tls_config(
    ech: &EchSettings,
    fingerprint: FingerprintType,
    allow_insecure: bool,
    alpn_override: Option<&[&str]>,
) -> Result<ClientConfig> {
    if !ech.is_enabled() {
        return fingerprint::build_fingerprinted_tls_config(
            fingerprint,
            allow_insecure,
            alpn_override,
        );
    }

    let ech_mode = build_ech_mode(ech)?;

    let provider = Arc::new(build_ech_provider(fingerprint));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // ECH requires TLS 1.3 only
    let mut config = if allow_insecure {
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::common::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_provider(provider)
            .with_ech(ech_mode)
            .map_err(|e| anyhow::anyhow!("ECH config error: {}", e))?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Set ALPN
    if let Some(protocols) = alpn_override {
        config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    } else {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }

    debug!(grease = ech.grease, has_config = ech.config_list.is_some(), "built ECH TLS config");
    Ok(config)
}

/// Build the ECH mode from settings
fn build_ech_mode(ech: &EchSettings) -> Result<EchMode> {
    if let Some(ref config_bytes) = ech.config_list {
        let config_list = EchConfigListBytes::from(config_bytes.clone());
        let ech_config = EchConfig::new(config_list, supported_hpke_suites())
            .map_err(|e| anyhow::anyhow!("failed to parse ECH config: {}", e))?;
        Ok(EchMode::from(ech_config))
    } else if ech.grease {
        let hpke_suite = supported_hpke_suites()
            .first()
            .ok_or_else(|| anyhow::anyhow!("no HPKE suites available for GREASE ECH"))?;
        let (public_key, _) = hpke_suite
            .generate_key_pair()
            .map_err(|e| anyhow::anyhow!("HPKE key generation failed: {}", e))?;
        Ok(EchMode::from(EchGreaseConfig::new(*hpke_suite, public_key)))
    } else {
        anyhow::bail!("ECH is not enabled")
    }
}

/// Build a CryptoProvider suitable for ECH (with optional fingerprinting)
fn build_ech_provider(fingerprint: FingerprintType) -> rustls::crypto::CryptoProvider {
    use rustls::crypto::ring as ring_provider;

    let default = ring_provider::default_provider();

    if fingerprint == FingerprintType::None {
        return default;
    }

    // Use fingerprinted cipher suites but keep the rest from ring
    let cipher_suites = match fingerprint {
        FingerprintType::Chrome | FingerprintType::Edge | FingerprintType::Android => {
            use rustls::crypto::ring::cipher_suite;
            vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ]
        }
        FingerprintType::Firefox => {
            use rustls::crypto::ring::cipher_suite;
            vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
            ]
        }
        _ => default.cipher_suites.clone(),
    };

    rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups: default.kx_groups,
        signature_verification_algorithms: default.signature_verification_algorithms,
        secure_random: default.secure_random,
        key_provider: default.key_provider,
    }
}

/// Parse base64-encoded ECH config list
pub fn parse_ech_config_base64(b64: &str) -> Result<Vec<u8>> {
    base64::decode_config(b64)
}

/// Resolve ECH configuration from DNS HTTPS records (RR type 65).
///
/// Queries the domain's HTTPS records and extracts ECH config (SvcParam key 5).
/// Returns `Ok(None)` if no ECH config is found or DNS lookup fails.
pub async fn resolve_ech_from_dns(domain: &str) -> Result<Option<Vec<u8>>> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::{RData, RecordType};
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare_https(),
        ResolverOpts::default(),
    );

    let lookup = match resolver.lookup(domain, RecordType::HTTPS).await {
        Ok(lookup) => lookup,
        Err(e) => {
            debug!(domain = domain, error = %e, "ECH DNS HTTPS lookup failed");
            return Ok(None);
        }
    };

    for record in lookup.record_iter() {
        if let Some(RData::HTTPS(ref svcb)) = record.data() {
            for (key, value) in svcb.svc_params() {
                if let (SvcParamKey::EchConfig, SvcParamValue::EchConfig(ref ech)) = (key, value) {
                    debug!(domain = domain, len = ech.0.len(), "ECH config found via DNS HTTPS");
                    return Ok(Some(ech.0.clone()));
                }
            }
        }
    }

    debug!(domain = domain, "no ECH config in DNS HTTPS records");
    Ok(None)
}

/// Build `EchSettings` from `TlsConfig`, optionally auto-fetching from DNS.
///
/// Priority: manual `ech-config` > `ech-auto` DNS fetch > `ech-grease`.
pub async fn resolve_ech_settings(config: &TlsConfig, domain: &str) -> Result<EchSettings> {
    let manual_config = config
        .ech_config
        .as_deref()
        .map(parse_ech_config_base64)
        .transpose()?;

    let config_list = if manual_config.is_some() {
        manual_config
    } else if config.ech_auto {
        resolve_ech_from_dns(domain).await?
    } else {
        None
    };

    Ok(EchSettings {
        config_list,
        grease: config.ech_grease,
        outer_sni: config.ech_outer_sni.clone(),
    })
}

/// Simple base64 decoder (no extra dependency)
mod base64 {
    use anyhow::Result;

    pub fn decode_config(input: &str) -> Result<Vec<u8>> {
        let input = input.trim().trim_end_matches('=');
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

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_settings_default() {
        let settings = EchSettings::default();
        assert!(!settings.is_enabled());
        assert!(settings.config_list.is_none());
        assert!(!settings.grease);
    }

    #[test]
    fn test_ech_settings_grease_enabled() {
        let settings = EchSettings {
            grease: true,
            ..Default::default()
        };
        assert!(settings.is_enabled());
    }

    #[test]
    fn test_ech_settings_config_enabled() {
        let settings = EchSettings {
            config_list: Some(vec![0x00, 0x01]),
            ..Default::default()
        };
        assert!(settings.is_enabled());
    }

    #[test]
    fn test_build_ech_mode_grease() {
        let settings = EchSettings {
            grease: true,
            ..Default::default()
        };
        let mode = build_ech_mode(&settings);
        assert!(mode.is_ok());
    }

    #[test]
    fn test_build_ech_mode_disabled() {
        let settings = EchSettings::default();
        let mode = build_ech_mode(&settings);
        assert!(mode.is_err());
    }

    #[test]
    fn test_build_ech_provider_none() {
        let provider = build_ech_provider(FingerprintType::None);
        assert!(!provider.cipher_suites.is_empty());
    }

    #[test]
    fn test_build_ech_provider_chrome() {
        let provider = build_ech_provider(FingerprintType::Chrome);
        // ECH requires TLS 1.3 only, so only TLS 1.3 cipher suites
        assert_eq!(provider.cipher_suites.len(), 3);
    }

    #[test]
    fn test_build_ech_tls_config_disabled() {
        let ech = EchSettings::default();
        let config =
            build_ech_tls_config(&ech, FingerprintType::Chrome, false, None).unwrap();
        // Falls back to fingerprinted config
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_build_ech_tls_config_grease() {
        let ech = EchSettings {
            grease: true,
            ..Default::default()
        };
        let config =
            build_ech_tls_config(&ech, FingerprintType::None, false, None).unwrap();
        assert_eq!(config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_parse_ech_config_base64() {
        // "hello" = "aGVsbG8="
        let bytes = parse_ech_config_base64("aGVsbG8=").unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_parse_ech_config_base64_url_safe() {
        let bytes = parse_ech_config_base64("aGVsbG8").unwrap();
        assert_eq!(bytes, b"hello");
    }
}
