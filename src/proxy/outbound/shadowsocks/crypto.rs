use anyhow::{bail, Result};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Md5, Digest as Md5Digest};
use sha1::Sha1;

/// Shadowsocks AEAD cipher kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    /// Parse cipher method name string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(CipherKind::Aes128Gcm),
            "aes-256-gcm" => Ok(CipherKind::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(CipherKind::ChaCha20Poly1305),
            other => bail!("unsupported shadowsocks cipher: {}", other),
        }
    }

    /// Key length in bytes
    pub fn key_len(&self) -> usize {
        match self {
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
            CipherKind::ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes (same as key length)
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    /// AEAD tag length in bytes (always 16 for all supported ciphers)
    pub fn tag_len(&self) -> usize {
        16
    }
}

/// Derive key from password using EVP_BytesToKey (OpenSSL compatible).
///
/// Algorithm: iterative MD5 hashing.
/// D_0 = MD5(password)
/// D_i = MD5(D_{i-1} || password)
/// Concatenate until we have at least key_len bytes.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev_hash: Option<Vec<u8>> = None;

    while key.len() < key_len {
        let mut hasher = Md5::new();
        if let Some(ref prev) = prev_hash {
            hasher.update(prev);
        }
        hasher.update(password);
        let hash = hasher.finalize().to_vec();
        key.extend_from_slice(&hash);
        prev_hash = Some(hash);
    }

    key.truncate(key_len);
    key
}

/// Derive subkey from master key and salt using HKDF-SHA1.
///
/// info = b"ss-subkey"
pub fn derive_subkey(key: &[u8], salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut subkey = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut subkey)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
    Ok(subkey)
}

/// AEAD cipher with nonce counter for Shadowsocks stream encryption.
pub struct AeadCipher {
    cipher_kind: CipherKind,
    key: Vec<u8>,
    nonce: u64,
}

impl AeadCipher {
    /// Create a new AEAD cipher with the given subkey.
    pub fn new(cipher_kind: CipherKind, subkey: Vec<u8>) -> Self {
        Self {
            cipher_kind,
            key: subkey,
            nonce: 0,
        }
    }

    /// Get the current nonce as a 12-byte LE-encoded array, then increment.
    fn nonce_bytes_and_increment(&mut self) -> [u8; 12] {
        let nonce = self.nonce_bytes();
        self.nonce += 1;
        nonce
    }

    /// Get the current nonce as 12-byte LE-encoded array (without incrementing).
    pub fn nonce_bytes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    /// Encrypt plaintext in place, returning ciphertext + tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce_bytes_and_increment();
        let mut buf = plaintext.to_vec();

        match self.cipher_kind {
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut buf)
                    .map_err(|e| anyhow::anyhow!("AES-128-GCM encrypt failed: {}", e))?;
                buf.extend_from_slice(&tag);
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut buf)
                    .map_err(|e| anyhow::anyhow!("AES-256-GCM encrypt failed: {}", e))?;
                buf.extend_from_slice(&tag);
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut buf)
                    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encrypt failed: {}", e))?;
                buf.extend_from_slice(&tag);
            }
        }

        Ok(buf)
    }

    /// Decrypt ciphertext (with appended tag), returning plaintext.
    pub fn decrypt(&mut self, ciphertext_with_tag: &[u8]) -> Result<Vec<u8>> {
        let tag_len = self.cipher_kind.tag_len();
        if ciphertext_with_tag.len() < tag_len {
            bail!("ciphertext too short: {} bytes, need at least {} for tag",
                ciphertext_with_tag.len(), tag_len);
        }

        let nonce = self.nonce_bytes_and_increment();
        let ct_len = ciphertext_with_tag.len() - tag_len;
        let mut buf = ciphertext_with_tag[..ct_len].to_vec();
        let tag = &ciphertext_with_tag[ct_len..];

        match self.cipher_kind {
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(&nonce),
                        b"",
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|e| anyhow::anyhow!("AES-128-GCM decrypt failed: {}", e))?;
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(&nonce),
                        b"",
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|e| anyhow::anyhow!("AES-256-GCM decrypt failed: {}", e))?;
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(&nonce),
                        b"",
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decrypt failed: {}", e))?;
            }
        }

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_kind_parse() {
        assert_eq!(CipherKind::from_str("aes-128-gcm").unwrap(), CipherKind::Aes128Gcm);
        assert_eq!(CipherKind::from_str("aes-256-gcm").unwrap(), CipherKind::Aes256Gcm);
        assert_eq!(
            CipherKind::from_str("chacha20-ietf-poly1305").unwrap(),
            CipherKind::ChaCha20Poly1305
        );
        assert_eq!(
            CipherKind::from_str("chacha20-poly1305").unwrap(),
            CipherKind::ChaCha20Poly1305
        );
        assert!(CipherKind::from_str("unknown").is_err());
    }

    #[test]
    fn cipher_kind_lengths() {
        assert_eq!(CipherKind::Aes128Gcm.key_len(), 16);
        assert_eq!(CipherKind::Aes256Gcm.key_len(), 32);
        assert_eq!(CipherKind::ChaCha20Poly1305.key_len(), 32);

        assert_eq!(CipherKind::Aes128Gcm.salt_len(), 16);
        assert_eq!(CipherKind::Aes256Gcm.salt_len(), 32);

        assert_eq!(CipherKind::Aes128Gcm.tag_len(), 16);
        assert_eq!(CipherKind::Aes256Gcm.tag_len(), 16);
        assert_eq!(CipherKind::ChaCha20Poly1305.tag_len(), 16);
    }

    #[test]
    fn evp_bytes_to_key_known_vector() {
        // Known test: password "test", key_len 16
        let key = evp_bytes_to_key(b"test", 16);
        assert_eq!(key.len(), 16);
        // MD5("test") = 098f6bcd4621d373cade4e832627b4f6
        assert_eq!(
            key,
            [0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73,
             0xca, 0xde, 0x4e, 0x83, 0x26, 0x27, 0xb4, 0xf6]
        );
    }

    #[test]
    fn evp_bytes_to_key_32() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_subkey_valid() {
        let key = vec![0u8; 32];
        let salt = vec![1u8; 32];
        let subkey = derive_subkey(&key, &salt, 32).unwrap();
        assert_eq!(subkey.len(), 32);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip_aes128() {
        let subkey = vec![0x42u8; 16];
        let mut enc = AeadCipher::new(CipherKind::Aes128Gcm, subkey.clone());
        let mut dec = AeadCipher::new(CipherKind::Aes128Gcm, subkey);

        let plaintext = b"hello world";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip_aes256() {
        let subkey = vec![0x42u8; 32];
        let mut enc = AeadCipher::new(CipherKind::Aes256Gcm, subkey.clone());
        let mut dec = AeadCipher::new(CipherKind::Aes256Gcm, subkey);

        let plaintext = b"hello world 256";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip_chacha() {
        let subkey = vec![0x42u8; 32];
        let mut enc = AeadCipher::new(CipherKind::ChaCha20Poly1305, subkey.clone());
        let mut dec = AeadCipher::new(CipherKind::ChaCha20Poly1305, subkey);

        let plaintext = b"chacha test data";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aead_nonce_increments() {
        let subkey = vec![0x42u8; 16];
        let mut cipher = AeadCipher::new(CipherKind::Aes128Gcm, subkey);
        assert_eq!(cipher.nonce, 0);

        cipher.encrypt(b"a").unwrap();
        assert_eq!(cipher.nonce, 1);

        cipher.encrypt(b"b").unwrap();
        assert_eq!(cipher.nonce, 2);
    }

    #[test]
    fn aead_decrypt_too_short() {
        let subkey = vec![0x42u8; 16];
        let mut cipher = AeadCipher::new(CipherKind::Aes128Gcm, subkey);
        assert!(cipher.decrypt(&[0u8; 10]).is_err());
    }
}
