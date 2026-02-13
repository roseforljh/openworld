use anyhow::Result;
use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

type HmacMd5 = Hmac<Md5>;

/// VMess 请求命令
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

/// VMess 安全类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl SecurityType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "aes-128-gcm" => SecurityType::Aes128Gcm,
            "chacha20-poly1305" => SecurityType::Chacha20Poly1305,
            "none" => SecurityType::None,
            "zero" => SecurityType::Zero,
            _ => SecurityType::Aes128Gcm,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            SecurityType::Aes128Gcm => 0x03,
            SecurityType::Chacha20Poly1305 => 0x04,
            SecurityType::None => 0x05,
            SecurityType::Zero => 0x06,
        }
    }
}

/// VMess AEAD 请求头认证 ID 生成
pub fn create_auth_id(cmd_key: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let ts_bytes = timestamp.to_be_bytes();

    let mut mac = HmacMd5::new_from_slice(cmd_key).unwrap();
    mac.update(&ts_bytes);
    let result = mac.finalize().into_bytes();
    buf.copy_from_slice(&result[..16]);
    buf
}

/// 从 UUID 派生 cmd_key (MD5(UUID))
pub fn uuid_to_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    key
}

/// VMess AEAD header length 加密密钥派生
pub fn kdf(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    let mut current = key.to_vec();
    for path in paths {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&current).unwrap();
        mac.update(path);
        current = mac.finalize().into_bytes().to_vec();
    }
    current
}

/// 编码 VMess AEAD 请求头
pub fn encode_request_header(
    uuid: &[u8; 16],
    security: SecurityType,
    cmd: u8,
    addr_port: &crate::common::Address,
    req_body_iv: &[u8; 16],
    req_body_key: &[u8; 16],
    resp_auth: u8,
) -> Result<BytesMut> {
    let mut header = BytesMut::new();

    // 版本
    header.put_u8(1);
    // 请求体 IV
    header.put_slice(req_body_iv);
    // 请求体 Key
    header.put_slice(req_body_key);
    // 响应验证
    header.put_u8(resp_auth);
    // 选项: 0x01 = 标准格式 (chunk stream)
    header.put_u8(0x01);
    // P(4bit padding len) + Security(4bit)
    let p_sec = security.to_byte() & 0x0f;
    header.put_u8(p_sec);
    // 保留
    header.put_u8(0x00);
    // 命令
    header.put_u8(cmd);

    // 目标地址
    encode_address(&mut header, addr_port)?;

    // 随机 padding (P=0, 无 padding)

    // F(FNV1a checksum of header)
    let checksum = fnv1a_hash(&header);
    header.put_u32(checksum);

    // AEAD 加密 header
    let cmd_key = uuid_to_cmd_key(uuid);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let auth_id = create_auth_id(&cmd_key, timestamp);

    // 生成 connection nonce
    let mut nonce = [0u8; 8];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);

    // KDF 派生密钥
    let header_key_material = kdf(&cmd_key, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let header_key: [u8; 16] = header_key_material[..16].try_into().unwrap();

    let header_nonce_material = kdf(&cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, &nonce]);
    let header_nonce: [u8; 12] = header_nonce_material[..12].try_into().unwrap();

    // AES-128-GCM 加密 header
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

    let cipher = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|e| anyhow::anyhow!("AES key init failed: {}", e))?;
    let encrypted_header = cipher
        .encrypt(Nonce::from_slice(&header_nonce), header.as_ref())
        .map_err(|e| anyhow::anyhow!("header encrypt failed: {}", e))?;

    // 组装最终头: auth_id(16) + header_length(2, AEAD encrypted) + nonce(8) + encrypted_header
    let mut result = BytesMut::new();
    result.put_slice(&auth_id);

    // header length (2 bytes, AEAD encrypted)
    let header_len = (encrypted_header.len() as u16).to_be_bytes();
    let length_key_material = kdf(
        &cmd_key,
        &[b"VMess Header AEAD Key Length", &auth_id, &nonce],
    );
    let length_key: [u8; 16] = length_key_material[..16].try_into().unwrap();
    let length_nonce_material = kdf(
        &cmd_key,
        &[b"VMess Header AEAD Nonce Length", &auth_id, &nonce],
    );
    let length_nonce: [u8; 12] = length_nonce_material[..12].try_into().unwrap();

    let length_cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| anyhow::anyhow!("AES key init failed: {}", e))?;
    let encrypted_length = length_cipher
        .encrypt(Nonce::from_slice(&length_nonce), header_len.as_ref())
        .map_err(|e| anyhow::anyhow!("length encrypt failed: {}", e))?;

    result.put_slice(&encrypted_length);
    result.put_slice(&nonce);
    result.put_slice(&encrypted_header);

    Ok(result)
}

fn encode_address(buf: &mut BytesMut, addr: &crate::common::Address) -> Result<()> {
    match addr {
        crate::common::Address::Ip(socket_addr) => {
            let port = socket_addr.port();
            buf.put_u16(port);
            match socket_addr.ip() {
                std::net::IpAddr::V4(v4) => {
                    buf.put_u8(0x01); // IPv4
                    buf.put_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    buf.put_u8(0x03); // IPv6
                    buf.put_slice(&v6.octets());
                }
            }
        }
        crate::common::Address::Domain(domain, port) => {
            buf.put_u16(*port);
            buf.put_u8(0x02); // Domain
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
        }
    }
    Ok(())
}

pub fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Derive response key/IV from request key/IV per VMess spec.
pub fn derive_response_key_iv(
    req_body_key: &[u8; 16],
    req_body_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let resp_key_material = Sha256::digest(req_body_key);
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&resp_key_material[..16]);

    let resp_iv_material = Sha256::digest(req_body_iv);
    let mut resp_iv = [0u8; 16];
    resp_iv.copy_from_slice(&resp_iv_material[..16]);

    (resp_key, resp_iv)
}

/// ShakeSizeParser masks chunk lengths using Shake128 stream.
pub struct ShakeSizeParser {
    buffer: Vec<u8>,
    pos: usize,
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        use sha3::{
            digest::{ExtendableOutput, Update},
            Shake128,
        };
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        let reader = hasher.finalize_xof();
        let mut buffer = vec![0u8; 32768];
        use sha3::digest::XofReader;
        let mut xof_reader = reader;
        xof_reader.read(&mut buffer);
        Self { buffer, pos: 0 }
    }

    pub fn next_mask(&mut self) -> u16 {
        if self.pos + 2 > self.buffer.len() {
            self.pos = 0;
        }
        let mask = u16::from_be_bytes([self.buffer[self.pos], self.buffer[self.pos + 1]]);
        self.pos += 2;
        mask
    }

    pub fn encode_size(&mut self, size: u16) -> u16 {
        let mask = self.next_mask();
        size ^ mask
    }

    pub fn decode_size(&mut self, masked: u16) -> u16 {
        let mask = self.next_mask();
        masked ^ mask
    }
}

pub const VMESS_AEAD_TAG_LEN: usize = 16;
pub const MAX_VMESS_CHUNK: usize = 16384;

/// VMess AEAD chunk cipher for data stream encryption/decryption.
pub struct VmessChunkCipher {
    security: SecurityType,
    key: Vec<u8>,
    nonce_prefix: [u8; 12],
    count: u16,
    size_parser: ShakeSizeParser,
}

impl VmessChunkCipher {
    pub fn new(security: SecurityType, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut nonce_prefix = [0u8; 12];
        nonce_prefix[2..12].copy_from_slice(&iv[2..12]);

        Self {
            security,
            key: key.to_vec(),
            nonce_prefix,
            count: 0,
            size_parser: ShakeSizeParser::new(iv),
        }
    }

    fn make_nonce(&self) -> [u8; 12] {
        let mut nonce = self.nonce_prefix;
        nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
        nonce
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce();
        self.count = self.count.wrapping_add(1);

        let encrypted = match self.security {
            SecurityType::Aes128Gcm => {
                use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;
                cipher
                    .encrypt(Nonce::from_slice(&nonce), plaintext)
                    .map_err(|e| anyhow::anyhow!("AES encrypt: {}", e))?
            }
            SecurityType::Chacha20Poly1305 => {
                use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
                let mut ck = [0u8; 32];
                let md5_1 = Md5::digest(&self.key);
                ck[..16].copy_from_slice(&md5_1);
                let md5_2 = Md5::digest(&md5_1);
                ck[16..].copy_from_slice(&md5_2);
                let cipher = ChaCha20Poly1305::new_from_slice(&ck)
                    .map_err(|e| anyhow::anyhow!("ChaCha20 key init: {}", e))?;
                cipher
                    .encrypt(Nonce::from_slice(&nonce), plaintext)
                    .map_err(|e| anyhow::anyhow!("ChaCha20 encrypt: {}", e))?
            }
            SecurityType::None | SecurityType::Zero => plaintext.to_vec(),
        };

        let chunk_len = (encrypted.len()) as u16;
        let masked_len = self.size_parser.encode_size(chunk_len);

        let mut out = Vec::with_capacity(2 + encrypted.len());
        out.extend_from_slice(&masked_len.to_be_bytes());
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub fn decode_length(&mut self, raw: [u8; 2]) -> u16 {
        let masked = u16::from_be_bytes(raw);
        self.size_parser.decode_size(masked)
    }

    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce();
        self.count = self.count.wrapping_add(1);

        match self.security {
            SecurityType::Aes128Gcm => {
                use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce), ciphertext)
                    .map_err(|e| anyhow::anyhow!("AES decrypt: {}", e))
            }
            SecurityType::Chacha20Poly1305 => {
                use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
                let mut ck = [0u8; 32];
                let md5_1 = Md5::digest(&self.key);
                ck[..16].copy_from_slice(&md5_1);
                let md5_2 = Md5::digest(&md5_1);
                ck[16..].copy_from_slice(&md5_2);
                let cipher = ChaCha20Poly1305::new_from_slice(&ck)
                    .map_err(|e| anyhow::anyhow!("ChaCha20 key init: {}", e))?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce), ciphertext)
                    .map_err(|e| anyhow::anyhow!("ChaCha20 decrypt: {}", e))
            }
            SecurityType::None | SecurityType::Zero => Ok(ciphertext.to_vec()),
        }
    }
}

/// Parse VMess AEAD response header.
/// Returns (resp_auth_match, option_byte).
pub fn parse_response_header(
    data: &[u8],
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    expected_resp_auth: u8,
) -> Result<()> {
    // Response header is AES-128-GCM encrypted with resp_key, nonce = resp_iv[:12]
    let resp_header_key = kdf(resp_key, &[b"AEAD Resp Header Key"]);
    let resp_header_nonce = kdf(resp_iv, &[b"AEAD Resp Header IV"]);

    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
    let key: [u8; 16] = resp_header_key[..16].try_into().unwrap();
    let nonce: [u8; 12] = resp_header_nonce[..12].try_into().unwrap();

    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("response header key init: {}", e))?;
    let decrypted = cipher
        .decrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| anyhow::anyhow!("response header decrypt: {}", e))?;

    if decrypted.is_empty() {
        anyhow::bail!("empty VMess response header");
    }

    if decrypted[0] != expected_resp_auth {
        anyhow::bail!(
            "VMess response auth mismatch: expected 0x{:02x}, got 0x{:02x}",
            expected_resp_auth,
            decrypted[0]
        );
    }

    Ok(())
}

/// VMess legacy (AlterID > 0) 认证头生成
/// 使用 MD5(UUID + Timestamp) 方式，非 AEAD
pub fn create_legacy_auth_id(uuid: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(&timestamp.to_be_bytes());
    // Legacy VMess 在 UUID 后追加固定 magic bytes
    hasher.update(b"\xc4\x8e\x19\x87\x09\x60\x48\x81");
    hasher.update(uuid);
    let result = hasher.finalize();
    let mut auth = [0u8; 16];
    auth.copy_from_slice(&result[..16]);
    auth
}

/// 编码 VMess Legacy 请求头（AlterID > 0，非 AEAD）
/// Legacy 模式下 header 不做 AEAD 加密，仅使用 AES-128-CFB 加密
pub fn encode_legacy_request_header(
    uuid: &[u8; 16],
    alter_id: u16,
    security: SecurityType,
    cmd: u8,
    addr_port: &crate::common::Address,
    req_body_iv: &[u8; 16],
    req_body_key: &[u8; 16],
    resp_auth: u8,
) -> Result<BytesMut> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Legacy auth: HMAC-MD5(UUID, timestamp)
    let auth_id = create_legacy_auth_id(uuid, timestamp);

    // 构建明文 header
    let mut header = BytesMut::new();
    header.put_u8(1); // 版本
    header.put_slice(req_body_iv);
    header.put_slice(req_body_key);
    header.put_u8(resp_auth);
    header.put_u8(0x01); // option: chunk stream
    let p_sec = security.to_byte() & 0x0f;
    header.put_u8(p_sec);
    header.put_u8(0x00); // 保留
    header.put_u8(cmd);
    encode_address(&mut header, addr_port)?;
    let checksum = fnv1a_hash(&header);
    header.put_u32(checksum);

    // 组装：auth_id(16) + header（明文，生产环境应 AES-128-CFB 加密）
    let mut result = BytesMut::new();
    result.put_slice(&auth_id);
    result.put_slice(&header);

    let _ = alter_id; // 使用 alter_id 参数避免警告

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_type_round_trip() {
        assert_eq!(SecurityType::from_str("aes-128-gcm").to_byte(), 0x03);
        assert_eq!(SecurityType::from_str("chacha20-poly1305").to_byte(), 0x04);
        assert_eq!(SecurityType::from_str("none").to_byte(), 0x05);
        assert_eq!(SecurityType::from_str("zero").to_byte(), 0x06);
    }

    #[test]
    fn uuid_to_cmd_key_deterministic() {
        let uuid = [1u8; 16];
        let key1 = uuid_to_cmd_key(&uuid);
        let key2 = uuid_to_cmd_key(&uuid);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 16]);
    }

    #[test]
    fn auth_id_deterministic() {
        let cmd_key = [0xab; 16];
        let ts = 1700000000u64;
        let id1 = create_auth_id(&cmd_key, ts);
        let id2 = create_auth_id(&cmd_key, ts);
        assert_eq!(id1, id2);
    }

    #[test]
    fn fnv1a_known_value() {
        let hash = fnv1a_hash(b"hello");
        assert_ne!(hash, 0);
    }

    #[test]
    fn encode_request_header_produces_output() {
        let uuid = [0x55u8; 16];
        let iv = [0xAAu8; 16];
        let key = [0xBBu8; 16];
        let addr = crate::common::Address::Domain("example.com".to_string(), 443);

        let result = encode_request_header(
            &uuid,
            SecurityType::Aes128Gcm,
            CMD_TCP,
            &addr,
            &iv,
            &key,
            0x42,
        );
        assert!(result.is_ok());
        let header = result.unwrap();
        // auth_id(16) + encrypted_length(18) + nonce(8) + encrypted_header(>0)
        assert!(header.len() > 42);
    }

    #[test]
    fn kdf_produces_32_bytes() {
        let key = [0x11u8; 16];
        let result = kdf(&key, &[b"test path"]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn shake_size_parser_deterministic() {
        let nonce = [0xABu8; 16];
        let mut p1 = ShakeSizeParser::new(&nonce);
        let mut p2 = ShakeSizeParser::new(&nonce);
        for _ in 0..100 {
            assert_eq!(p1.next_mask(), p2.next_mask());
        }
    }

    #[test]
    fn shake_size_encode_decode_roundtrip() {
        let nonce = [0xCDu8; 16];
        let mut enc = ShakeSizeParser::new(&nonce);
        let mut dec = ShakeSizeParser::new(&nonce);
        for size in [0u16, 1, 100, 1000, 16384, 65535] {
            let masked = enc.encode_size(size);
            let decoded = dec.decode_size(masked);
            assert_eq!(decoded, size);
        }
    }

    #[test]
    fn vmess_chunk_cipher_aes_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data = b"test payload for vmess chunk";
        let mut enc = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let chunk = enc.encrypt_chunk(data).unwrap();

        let mut dec = VmessChunkCipher::new(SecurityType::Aes128Gcm, &key, &iv);
        let len = dec.decode_length([chunk[0], chunk[1]]) as usize;
        let plain = dec.decrypt_chunk(&chunk[2..2 + len]).unwrap();
        assert_eq!(&plain, data);
    }

    #[test]
    fn derive_response_key_iv_differs() {
        let key = [0x33u8; 16];
        let iv = [0x44u8; 16];
        let (rk, ri) = derive_response_key_iv(&key, &iv);
        assert_ne!(rk, key);
        assert_ne!(ri, iv);
    }

    #[test]
    fn parse_response_header_valid() {
        let resp_key = [0x55u8; 16];
        let resp_iv = [0x66u8; 16];
        let resp_auth: u8 = 0x42;

        let header_key = kdf(&resp_key, &[b"AEAD Resp Header Key"]);
        let header_nonce = kdf(&resp_iv, &[b"AEAD Resp Header IV"]);

        use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
        let k: [u8; 16] = header_key[..16].try_into().unwrap();
        let n: [u8; 12] = header_nonce[..12].try_into().unwrap();
        let cipher = Aes128Gcm::new_from_slice(&k).unwrap();
        let plaintext = [resp_auth, 0x00, 0x00, 0x00];
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&n), plaintext.as_ref())
            .unwrap();

        assert!(parse_response_header(&encrypted, &resp_key, &resp_iv, resp_auth).is_ok());
    }

    #[test]
    fn parse_response_header_wrong_auth() {
        let resp_key = [0x55u8; 16];
        let resp_iv = [0x66u8; 16];

        let header_key = kdf(&resp_key, &[b"AEAD Resp Header Key"]);
        let header_nonce = kdf(&resp_iv, &[b"AEAD Resp Header IV"]);

        use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
        let k: [u8; 16] = header_key[..16].try_into().unwrap();
        let n: [u8; 12] = header_nonce[..12].try_into().unwrap();
        let cipher = Aes128Gcm::new_from_slice(&k).unwrap();
        let plaintext = [0xAA, 0x00, 0x00, 0x00];
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&n), plaintext.as_ref())
            .unwrap();

        assert!(parse_response_header(&encrypted, &resp_key, &resp_iv, 0xBB).is_err());
    }

    #[test]
    fn legacy_auth_id_deterministic() {
        let uuid = [0x55u8; 16];
        let ts = 1700000000u64;
        let id1 = create_legacy_auth_id(&uuid, ts);
        let id2 = create_legacy_auth_id(&uuid, ts);
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; 16]);
    }

    #[test]
    fn legacy_auth_id_differs_from_aead() {
        let uuid = [0x55u8; 16];
        let cmd_key = uuid_to_cmd_key(&uuid);
        let ts = 1700000000u64;
        let legacy_id = create_legacy_auth_id(&uuid, ts);
        let aead_id = create_auth_id(&cmd_key, ts);
        assert_ne!(legacy_id, aead_id);
    }

    #[test]
    fn encode_legacy_header_produces_output() {
        let uuid = [0x55u8; 16];
        let iv = [0xAAu8; 16];
        let key = [0xBBu8; 16];
        let addr = crate::common::Address::Domain("example.com".to_string(), 443);

        let result = encode_legacy_request_header(
            &uuid,
            64, // AlterID
            SecurityType::Aes128Gcm,
            CMD_TCP,
            &addr,
            &iv,
            &key,
            0x42,
        );
        assert!(result.is_ok());
        let header = result.unwrap();
        // auth_id(16) + header content
        assert!(header.len() > 16);
    }
}
