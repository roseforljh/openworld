use anyhow::{bail, Result};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

/// PBKDF2 iteration count for key derivation
const PBKDF2_ITERATIONS: u32 = 100_000;

/// AES-256-GCM key length in bytes
const KEY_LEN: usize = 32;

/// Salt length in bytes
const SALT_LEN: usize = 8;

/// Nonce length in bytes (AES-GCM standard)
const NONCE_LEN: usize = 12;

/// Minimum encrypted file size: salt + nonce + tag (no plaintext)
const MIN_ENCRYPTED_LEN: usize = SALT_LEN + NONCE_LEN + 16;

/// Derive a 32-byte key from password and salt using PBKDF2-HMAC-SHA256.
///
/// Manual implementation using hmac + sha2 crates (no pbkdf2 crate needed).
fn pbkdf2_derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    // PBKDF2 with dkLen = 32 bytes = one block for HMAC-SHA256 (output is 32 bytes).
    // U_1 = PRF(password, salt || INT_32_BE(1))
    // U_i = PRF(password, U_{i-1})
    // DK = U_1 ^ U_2 ^ ... ^ U_c

    let mut block_input = Vec::with_capacity(salt.len() + 4);
    block_input.extend_from_slice(salt);
    block_input.extend_from_slice(&1u32.to_be_bytes()); // block index = 1

    // U_1
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC can take key of any size");
    mac.update(&block_input);
    let u1 = mac.finalize().into_bytes();

    let mut result = [0u8; KEY_LEN];
    result.copy_from_slice(&u1);

    let mut u_prev = u1;

    for _ in 1..iterations {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC can take key of any size");
        mac.update(&u_prev);
        let u_current = mac.finalize().into_bytes();

        for (r, u) in result.iter_mut().zip(u_current.iter()) {
            *r ^= u;
        }

        u_prev = u_current;
    }

    result
}

/// Encrypt config data with AES-256-GCM.
///
/// Output format: `[8B salt][12B nonce][encrypted_data][16B tag]`
///
/// The tag is appended by AES-GCM as part of the ciphertext output.
pub fn encrypt_config(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes);

    // Derive key
    let key = pbkdf2_derive_key(password.as_bytes(), &salt, PBKDF2_ITERATIONS);

    // Encrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    // Assemble output: salt || nonce || ciphertext (includes 16-byte tag)
    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt config data encrypted with `encrypt_config`.
///
/// Expected input format: `[8B salt][12B nonce][encrypted_data][16B tag]`
pub fn decrypt_config(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        bail!(
            "encrypted data too short: {} bytes, minimum {}",
            encrypted.len(),
            MIN_ENCRYPTED_LEN
        );
    }

    let salt = &encrypted[..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    // Derive key from password + salt
    let key = pbkdf2_derive_key(password.as_bytes(), salt, PBKDF2_ITERATIONS);

    // Decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or corrupted data"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let plaintext = b"mixed-port: 7890\nlog-level: info\n";
        let password = "test-password-123";

        let encrypted = encrypt_config(plaintext, password).unwrap();
        let decrypted = decrypt_config(&encrypted, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let password = b"deterministic-test";
        let salt = b"fixdsalt";

        let key1 = pbkdf2_derive_key(password, salt, PBKDF2_ITERATIONS);
        let key2 = pbkdf2_derive_key(password, salt, PBKDF2_ITERATIONS);

        assert_eq!(key1, key2, "same password+salt must produce same key");
    }

    #[test]
    fn wrong_password_fails() {
        let plaintext = b"secret data here";
        let encrypted = encrypt_config(plaintext, "correct-password").unwrap();

        let result = decrypt_config(&encrypted, "wrong-password");
        assert!(result.is_err(), "decryption with wrong password must fail");
    }

    #[test]
    fn empty_data_roundtrip() {
        let plaintext = b"";
        let password = "empty-data-test";

        let encrypted = encrypt_config(plaintext, password).unwrap();
        let decrypted = decrypt_config(&encrypted, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_data_fails() {
        let plaintext = b"important config data";
        let password = "tamper-test";

        let mut encrypted = encrypt_config(plaintext, password).unwrap();

        // Tamper with the ciphertext (flip a byte in the middle)
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        let result = decrypt_config(&encrypted, password);
        assert!(result.is_err(), "decryption of tampered data must fail");
    }

    #[test]
    fn encrypted_data_has_correct_overhead() {
        let plaintext = b"hello world";
        let encrypted = encrypt_config(plaintext, "size-test").unwrap();

        // salt(8) + nonce(12) + plaintext(11) + tag(16) = 47
        assert_eq!(encrypted.len(), SALT_LEN + NONCE_LEN + plaintext.len() + 16);
    }

    #[test]
    fn too_short_data_rejected() {
        let result = decrypt_config(&[0u8; 10], "password");
        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_differ() {
        let plaintext = b"same input";
        let password = "same-password";

        let enc1 = encrypt_config(plaintext, password).unwrap();
        let enc2 = encrypt_config(plaintext, password).unwrap();

        // Random salt/nonce means ciphertexts differ
        assert_ne!(
            enc1, enc2,
            "two encryptions should differ due to random salt/nonce"
        );

        // But both decrypt to the same plaintext
        assert_eq!(decrypt_config(&enc1, password).unwrap(), plaintext);
        assert_eq!(decrypt_config(&enc2, password).unwrap(), plaintext);
    }
}
