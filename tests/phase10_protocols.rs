//! Phase 10: Protocol Integration Tests
//!
//! Tests for Shadowsocks and Trojan protocol integration, covering:
//! - OutboundManager protocol registration (shadowsocks, ss, trojan, unsupported)
//! - Shadowsocks AEAD frame encode/decode (multi-frame, empty payload, max-length frame)
//! - Shadowsocks key derivation (EVP_BytesToKey edge cases)
//! - Trojan password hashing (SHA224 properties)

use openworld::app::outbound_manager::OutboundManager;
use openworld::config::types::{OutboundConfig, OutboundSettings};
use openworld::proxy::outbound::shadowsocks::crypto::{
    derive_subkey, evp_bytes_to_key, AeadCipher, CipherKind,
};
use openworld::proxy::outbound::trojan::protocol::password_hash;

// ---------------------------------------------------------------------------
// Helper: build a minimal OutboundConfig for a given protocol
// ---------------------------------------------------------------------------

fn make_ss_config(tag: &str, protocol: &str) -> OutboundConfig {
    OutboundConfig {
        tag: tag.to_string(),
        protocol: protocol.to_string(),
        settings: OutboundSettings {
            address: Some("127.0.0.1".to_string()),
            port: Some(8388),
            password: Some("test-password".to_string()),
            method: Some("aes-256-gcm".to_string()),
            ..Default::default()
        },
    }
}

fn make_trojan_config(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: tag.to_string(),
        protocol: "trojan".to_string(),
        settings: OutboundSettings {
            address: Some("127.0.0.1".to_string()),
            port: Some(443),
            password: Some("trojan-password".to_string()),
            ..Default::default()
        },
    }
}

fn make_direct_config() -> OutboundConfig {
    OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }
}

// ===========================================================================
// 1. OutboundManager Registration Tests
// ===========================================================================

/// Verify that protocol "shadowsocks" can be registered via OutboundManager.
#[test]
fn outbound_manager_register_shadowsocks() {
    let configs = vec![
        make_direct_config(),
        make_ss_config("ss-out", "shadowsocks"),
    ];
    let mgr = OutboundManager::new(&configs, &[]).expect("should register shadowsocks");
    assert!(
        mgr.get("ss-out").is_some(),
        "shadowsocks outbound should be retrievable by tag"
    );
}

/// Verify that protocol shorthand "ss" is accepted as an alias for shadowsocks.
#[test]
fn outbound_manager_register_ss_shorthand() {
    let configs = vec![make_direct_config(), make_ss_config("ss-alias", "ss")];
    let mgr = OutboundManager::new(&configs, &[]).expect("should register 'ss' shorthand");
    assert!(
        mgr.get("ss-alias").is_some(),
        "'ss' shorthand outbound should be retrievable by tag"
    );
}

/// Verify that protocol "trojan" can be registered via OutboundManager.
/// Trojan requires TLS which needs a CryptoProvider to be installed first.
#[test]
fn outbound_manager_register_trojan() {
    // Trojan builds a TLS transport internally, so a CryptoProvider must be available
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let configs = vec![make_direct_config(), make_trojan_config("trojan-out")];
    let mgr = OutboundManager::new(&configs, &[]).expect("should register trojan");
    assert!(
        mgr.get("trojan-out").is_some(),
        "trojan outbound should be retrievable by tag"
    );
}

/// Verify that an unsupported protocol causes OutboundManager::new to return Err.
#[test]
fn outbound_manager_unsupported_protocol_error() {
    let configs = vec![OutboundConfig {
        tag: "bad".to_string(),
        protocol: "not-a-real-protocol".to_string(),
        settings: OutboundSettings::default(),
    }];
    let result = OutboundManager::new(&configs, &[]);
    assert!(
        result.is_err(),
        "unsupported protocol should return an error"
    );
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error for unsupported protocol"),
    };
    assert!(
        err_msg.contains("unsupported"),
        "error message should mention 'unsupported', got: {}",
        err_msg
    );
}

// ===========================================================================
// 2. Shadowsocks AEAD Frame Encode/Decode Tests
// ===========================================================================

/// Helper: create a matched encrypt/decrypt cipher pair with the specified CipherKind.
fn make_cipher_pair(kind: CipherKind) -> (AeadCipher, AeadCipher) {
    let key_len = kind.key_len();
    let subkey = vec![0xABu8; key_len];
    let enc = AeadCipher::new(kind, subkey.clone());
    let dec = AeadCipher::new(kind, subkey);
    (enc, dec)
}

/// Multiple frames encrypted sequentially should each decrypt correctly,
/// verifying that the nonce counter stays in sync between encoder and decoder.
#[test]
fn ss_aead_multi_frame_roundtrip() {
    for kind in [
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::ChaCha20Poly1305,
    ] {
        let (mut enc, mut dec) = make_cipher_pair(kind);

        let messages: Vec<&[u8]> = vec![
            b"frame-1 hello",
            b"frame-2 world",
            b"frame-3 the quick brown fox jumps over the lazy dog",
            b"frame-4 short",
        ];

        for (i, msg) in messages.iter().enumerate() {
            let ct = enc.encrypt(msg).expect("encrypt should succeed");
            // Ciphertext length = plaintext length + 16-byte tag
            assert_eq!(
                ct.len(),
                msg.len() + kind.tag_len(),
                "frame {} ciphertext length mismatch for {:?}",
                i,
                kind
            );
            let pt = dec.decrypt(&ct).expect("decrypt should succeed");
            assert_eq!(
                &pt, msg,
                "frame {} decrypted plaintext mismatch for {:?}",
                i, kind
            );
        }
    }
}

/// An empty payload should encrypt and decrypt correctly (resulting ciphertext
/// is just the 16-byte AEAD tag).
#[test]
fn ss_aead_empty_payload() {
    for kind in [
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::ChaCha20Poly1305,
    ] {
        let (mut enc, mut dec) = make_cipher_pair(kind);

        let ct = enc.encrypt(b"").expect("encrypt empty should succeed");
        assert_eq!(
            ct.len(),
            kind.tag_len(),
            "empty payload ciphertext should be exactly tag_len for {:?}",
            kind
        );

        let pt = dec.decrypt(&ct).expect("decrypt empty should succeed");
        assert!(
            pt.is_empty(),
            "decrypted empty payload should be empty for {:?}",
            kind
        );
    }
}

/// A maximum-length frame (0x3FFF = 16383 bytes) should encrypt and decrypt
/// correctly. This is the largest payload allowed in a single Shadowsocks AEAD frame.
#[test]
fn ss_aead_max_length_frame() {
    let max_len: usize = 0x3FFF; // 16383

    for kind in [
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::ChaCha20Poly1305,
    ] {
        let (mut enc, mut dec) = make_cipher_pair(kind);

        // Fill with a repeating pattern so we can verify content integrity
        let payload: Vec<u8> = (0..max_len).map(|i| (i % 256) as u8).collect();
        assert_eq!(payload.len(), max_len);

        let ct = enc
            .encrypt(&payload)
            .expect("encrypt max frame should succeed");
        assert_eq!(
            ct.len(),
            max_len + kind.tag_len(),
            "max-length ciphertext size mismatch for {:?}",
            kind
        );

        let pt = dec.decrypt(&ct).expect("decrypt max frame should succeed");
        assert_eq!(
            pt.len(),
            max_len,
            "decrypted max-length plaintext size mismatch for {:?}",
            kind
        );
        assert_eq!(
            pt, payload,
            "max-length plaintext content mismatch for {:?}",
            kind
        );
    }
}

// ===========================================================================
// 3. Shadowsocks Key Derivation Tests
// ===========================================================================

/// EVP_BytesToKey with an empty password should still produce a key of the
/// requested length (MD5 of empty input is well-defined).
#[test]
fn ss_evp_bytes_to_key_empty_password() {
    let key16 = evp_bytes_to_key(b"", 16);
    assert_eq!(
        key16.len(),
        16,
        "key length should be 16 even for empty password"
    );

    let key32 = evp_bytes_to_key(b"", 32);
    assert_eq!(
        key32.len(),
        32,
        "key length should be 32 even for empty password"
    );

    // MD5("") = d41d8cd98f00b204e9800998ecf8427e, so the first 16 bytes are known
    assert_eq!(
        key16,
        [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e
        ],
        "EVP_BytesToKey with empty password should produce MD5 of empty string"
    );
}

/// Different passwords must produce different derived keys.
#[test]
fn ss_evp_bytes_to_key_different_passwords() {
    let key_a = evp_bytes_to_key(b"password-alpha", 32);
    let key_b = evp_bytes_to_key(b"password-beta", 32);
    assert_ne!(
        key_a, key_b,
        "different passwords must produce different keys"
    );

    // Also verify determinism: same password yields same key
    let key_a2 = evp_bytes_to_key(b"password-alpha", 32);
    assert_eq!(
        key_a, key_a2,
        "same password must always produce the same key"
    );
}

/// derive_subkey with the same master key but different salts must produce
/// different subkeys.
#[test]
fn ss_derive_subkey_different_salts() {
    let master_key = vec![0x42u8; 32];
    let salt_a = vec![0x01u8; 32];
    let salt_b = vec![0x02u8; 32];

    let sub_a = derive_subkey(&master_key, &salt_a, 32).expect("derive_subkey should succeed");
    let sub_b = derive_subkey(&master_key, &salt_b, 32).expect("derive_subkey should succeed");

    assert_ne!(
        sub_a, sub_b,
        "different salts must produce different subkeys"
    );
}

// ===========================================================================
// 4. Trojan Protocol Tests
// ===========================================================================

/// Different passwords must produce different SHA224 hex hashes.
#[test]
fn trojan_different_passwords_different_hashes() {
    let h1 = password_hash("password-one");
    let h2 = password_hash("password-two");
    assert_ne!(
        h1, h2,
        "different passwords must produce different Trojan hashes"
    );
}

/// SHA224 hex encoding length must always be exactly 56 characters
/// (SHA224 = 28 bytes = 56 hex characters), regardless of input.
#[test]
fn trojan_sha224_hash_length_is_56() {
    let test_passwords = [
        "",
        "a",
        "short",
        "a-medium-length-password",
        "a-very-very-long-password-that-exceeds-typical-lengths-significantly-0123456789",
    ];

    for pw in test_passwords {
        let h = password_hash(pw);
        assert_eq!(
            h.len(),
            56,
            "SHA224 hex hash of {:?} should be 56 chars, got {}",
            pw,
            h.len()
        );
        // All characters should be lowercase hex
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should contain only hex digits, got: {}",
            h
        );
    }
}

/// password_hash must be deterministic: same input always produces same output.
#[test]
fn trojan_password_hash_deterministic() {
    let h1 = password_hash("deterministic-test");
    let h2 = password_hash("deterministic-test");
    assert_eq!(h1, h2, "same password must always produce the same hash");
}
