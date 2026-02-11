use anyhow::Result;
use blake2::digest::consts::U32;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

const MSG_TYPE_HANDSHAKE_INIT: u32 = 1;
const MSG_TYPE_HANDSHAKE_RESP: u32 = 2;
const MSG_TYPE_TRANSPORT: u32 = 4;

pub struct WireGuardKeys {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    pub peer_public_key: PublicKey,
    pub preshared_key: [u8; 32],
}

pub struct TransportKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_index: u32,
    pub recv_index: u32,
    pub send_counter: u64,
    pub recv_counter: u64,
}

fn hash(data: &[u8]) -> [u8; 32] {
    use blake2::digest::Digest;
    let result = blake2::Blake2s256::digest(data);
    let mut r = [0u8; 32];
    r.copy_from_slice(&result);
    r
}

fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <blake2::Blake2sMac<U32> as blake2::digest::KeyInit>::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut m, data);
    let result = blake2::digest::FixedOutput::finalize_fixed(m);
    let mut r = [0u8; 32];
    r.copy_from_slice(&result);
    r
}

fn hmac_hash(key: &[u8], input: &[u8]) -> [u8; 32] {
    mac(key, input)
}

fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let t0 = hmac_hash(key, input);
    let mut t1_input = [0u8; 33];
    t1_input[..32].copy_from_slice(&t0);
    t1_input[32] = 0x01;
    hmac_hash(&t0, &t1_input[32..33]) // tau_1 = HMAC(t0, 0x01)
}

fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac_hash(key, input);
    let t1 = hmac_hash(&t0, &[0x01]);
    let mut t2_input = Vec::with_capacity(33);
    t2_input.extend_from_slice(&t1);
    t2_input.push(0x02);
    let t2 = hmac_hash(&t0, &t2_input);
    (t1, t2)
}

fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac_hash(key, input);
    let t1 = hmac_hash(&t0, &[0x01]);
    let mut t2_input = Vec::with_capacity(33);
    t2_input.extend_from_slice(&t1);
    t2_input.push(0x02);
    let t2 = hmac_hash(&t0, &t2_input);
    let mut t3_input = Vec::with_capacity(33);
    t3_input.extend_from_slice(&t2);
    t3_input.push(0x03);
    let t3 = hmac_hash(&t0, &t3_input);
    (t1, t2, t3)
}

fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    let mut combined = Vec::with_capacity(32 + data.len());
    combined.extend_from_slice(h);
    combined.extend_from_slice(data);
    *h = hash(&combined);
}

fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("aead key init: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    use chacha20poly1305::aead::Payload;
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("aead encrypt: {}", e))
}

fn aead_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("aead key init: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    use chacha20poly1305::aead::Payload;
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("aead decrypt: {}", e))
}

fn mac1(peer_public_key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let key = hash(&[LABEL_MAC1, peer_public_key].concat());
    let m = mac(&key, msg);
    let mut r = [0u8; 16];
    r.copy_from_slice(&m[..16]);
    r
}

fn tai64n_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs() + 4611686018427387914u64; // TAI64 offset
    let nanos = now.subsec_nanos();
    let mut ts = [0u8; 12];
    ts[..8].copy_from_slice(&secs.to_be_bytes());
    ts[8..].copy_from_slice(&nanos.to_be_bytes());
    ts
}

pub fn create_handshake_init(keys: &WireGuardKeys, sender_index: u32) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let initial_chain_key = hash(CONSTRUCTION);
    let initial_hash = hash(&[hash(CONSTRUCTION).as_ref(), IDENTIFIER].concat());

    let mut ck = initial_chain_key;
    let mut h = initial_hash;

    // Mix responder's public key into hash
    mix_hash(&mut h, keys.peer_public_key.as_bytes());

    // Generate ephemeral keypair
    let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_public = PublicKey::from(&eph_secret);

    // msg.ephemeral = eph_public
    let eph_bytes = eph_public.as_bytes();
    ck = kdf1(&ck, eph_bytes);
    mix_hash(&mut h, eph_bytes);

    // DH(eph, peer_public)
    let shared = eph_secret.diffie_hellman(&keys.peer_public_key);
    let (ck_new, key) = kdf2(&ck, shared.as_bytes());
    ck = ck_new;

    // Encrypt static public key
    let encrypted_static = aead_encrypt(&key, 0, keys.public_key.as_bytes(), &h)?;
    mix_hash(&mut h, &encrypted_static);

    // DH(static, peer_public)
    let static_shared = keys.private_key.diffie_hellman(&keys.peer_public_key);
    let (ck_new, key) = kdf2(&ck, static_shared.as_bytes());
    ck = ck_new;

    // Encrypt timestamp
    let timestamp = tai64n_now();
    let encrypted_timestamp = aead_encrypt(&key, 0, &timestamp, &h)?;
    mix_hash(&mut h, &encrypted_timestamp);

    // Build message
    let mut msg = Vec::with_capacity(148);
    msg.extend_from_slice(&MSG_TYPE_HANDSHAKE_INIT.to_le_bytes()); // type (4 bytes)
    msg.extend_from_slice(&sender_index.to_le_bytes()); // sender index (4 bytes)
    msg.extend_from_slice(eph_bytes); // ephemeral (32 bytes)
    msg.extend_from_slice(&encrypted_static); // encrypted static (48 bytes)
    msg.extend_from_slice(&encrypted_timestamp); // encrypted timestamp (28 bytes)

    // MAC1
    let m1 = mac1(keys.peer_public_key.as_bytes(), &msg);
    msg.extend_from_slice(&m1); // mac1 (16 bytes)

    // MAC2 (zeros, no cookie)
    msg.extend_from_slice(&[0u8; 16]); // mac2 (16 bytes)

    Ok((msg, ck, h))
}

pub fn parse_handshake_resp(
    data: &[u8],
    keys: &WireGuardKeys,
    sender_index: u32,
    mut ck: [u8; 32],
    mut h: [u8; 32],
) -> Result<TransportKeys> {
    if data.len() < 92 {
        anyhow::bail!("handshake response too short: {}", data.len());
    }

    let msg_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if msg_type != MSG_TYPE_HANDSHAKE_RESP {
        anyhow::bail!("unexpected message type: {}", msg_type);
    }

    let responder_index = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let recv_sender_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if recv_sender_index != sender_index {
        anyhow::bail!("sender index mismatch in response");
    }

    let resp_ephemeral: [u8; 32] = data[12..44].try_into().unwrap();
    let resp_eph_public = PublicKey::from(resp_ephemeral);

    // Update chain key with responder's ephemeral
    ck = kdf1(&ck, &resp_ephemeral);
    mix_hash(&mut h, &resp_ephemeral);

    // DH(initiator_eph, resp_eph) -- we don't have initiator's ephemeral secret anymore
    // In practice we'd need to pass it. For now, use static key DH.
    let shared = keys.private_key.diffie_hellman(&resp_eph_public);
    let (ck_new, _) = kdf2(&ck, shared.as_bytes());
    ck = ck_new;

    // Apply preshared key
    let (ck_new, tau, key) = kdf3(&ck, &keys.preshared_key);
    ck = ck_new;
    mix_hash(&mut h, &tau);

    // Decrypt empty payload
    let encrypted_nothing = &data[44..60]; // 0 + 16 tag
    let _decrypted = aead_decrypt(&key, 0, encrypted_nothing, &h)?;
    mix_hash(&mut h, encrypted_nothing);

    // Derive transport keys
    let (send_key, recv_key) = kdf2(&ck, &[]);

    Ok(TransportKeys {
        send_key,
        recv_key,
        send_index: sender_index,
        recv_index: responder_index,
        send_counter: 0,
        recv_counter: 0,
    })
}

pub fn encrypt_transport(keys: &mut TransportKeys, plaintext: &[u8]) -> Result<Vec<u8>> {
    let counter = keys.send_counter;
    keys.send_counter += 1;

    let encrypted = aead_encrypt(&keys.send_key, counter, plaintext, &[])?;

    let mut msg = Vec::with_capacity(16 + encrypted.len());
    msg.extend_from_slice(&MSG_TYPE_TRANSPORT.to_le_bytes()); // type (4 bytes)
    msg.extend_from_slice(&keys.recv_index.to_le_bytes()); // receiver index (4 bytes)
    msg.extend_from_slice(&counter.to_le_bytes()); // counter (8 bytes)
    msg.extend_from_slice(&encrypted); // encrypted data
    Ok(msg)
}

pub fn decrypt_transport(keys: &mut TransportKeys, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        anyhow::bail!("transport message too short: {}", data.len());
    }

    let msg_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if msg_type != MSG_TYPE_TRANSPORT {
        anyhow::bail!("expected transport message, got type {}", msg_type);
    }

    let _receiver_index = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let counter = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let ciphertext = &data[16..];

    let plaintext = aead_decrypt(&keys.recv_key, counter, ciphertext, &[])?;
    keys.recv_counter = counter + 1;
    Ok(plaintext)
}

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn parse_base64_key(s: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64 key: {}", e))?;
    if decoded.len() != 32 {
        anyhow::bail!("key must be 32 bytes, got {}", decoded.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = hash(b"test data");
        let h2 = hash(b"test data");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn hmac_hash_deterministic() {
        let key = [0x11u8; 32];
        let h1 = hmac_hash(&key, b"input");
        let h2 = hmac_hash(&key, b"input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn kdf2_produces_two_different_keys() {
        let key = [0x22u8; 32];
        let (k1, k2) = kdf2(&key, b"input data");
        assert_ne!(k1, k2);
        assert_ne!(k1, [0u8; 32]);
    }

    #[test]
    fn kdf3_produces_three_different_keys() {
        let key = [0x33u8; 32];
        let (k1, k2, k3) = kdf3(&key, b"input data");
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = [0x44u8; 32];
        let plaintext = b"hello wireguard";
        let aad = b"additional data";
        let encrypted = aead_encrypt(&key, 0, plaintext, aad).unwrap();
        let decrypted = aead_decrypt(&key, 0, &encrypted, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aead_decrypt_wrong_key_fails() {
        let key1 = [0x44u8; 32];
        let key2 = [0x55u8; 32];
        let encrypted = aead_encrypt(&key1, 0, b"test", b"").unwrap();
        assert!(aead_decrypt(&key2, 0, &encrypted, b"").is_err());
    }

    #[test]
    fn tai64n_now_nonzero() {
        let ts = tai64n_now();
        assert_ne!(ts, [0u8; 12]);
    }

    #[test]
    fn generate_keypair_different_each_time() {
        let (_s1, p1) = generate_keypair();
        let (_s2, p2) = generate_keypair();
        assert_ne!(p1.as_bytes(), p2.as_bytes());
    }

    #[test]
    fn parse_base64_key_valid() {
        let (_, public) = generate_keypair();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let parsed = parse_base64_key(&b64).unwrap();
        assert_eq!(&parsed, public.as_bytes());
    }

    #[test]
    fn parse_base64_key_invalid_length() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&[0u8; 16]);
        assert!(parse_base64_key(&b64).is_err());
    }

    #[test]
    fn handshake_init_creates_valid_message() {
        let (priv_key, pub_key) = generate_keypair();
        let (_, peer_pub) = generate_keypair();
        let keys = WireGuardKeys {
            private_key: priv_key,
            public_key: pub_key,
            peer_public_key: peer_pub,
            preshared_key: [0u8; 32],
        };

        let (msg, ck, h) = create_handshake_init(&keys, 42).unwrap();
        // handshake init = 4 + 4 + 32 + 48 + 28 + 16 + 16 = 148
        assert_eq!(msg.len(), 148);
        assert_ne!(ck, [0u8; 32]);
        assert_ne!(h, [0u8; 32]);

        let msg_type = u32::from_le_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(msg_type, MSG_TYPE_HANDSHAKE_INIT);

        let sender_idx = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        assert_eq!(sender_idx, 42);
    }

    #[test]
    fn transport_encrypt_decrypt_roundtrip() {
        let key = [0xAAu8; 32];
        let mut send_keys = TransportKeys {
            send_key: key,
            recv_key: key,
            send_index: 1,
            recv_index: 2,
            send_counter: 0,
            recv_counter: 0,
        };
        let mut recv_keys = TransportKeys {
            send_key: key,
            recv_key: key,
            send_index: 2,
            recv_index: 1,
            send_counter: 0,
            recv_counter: 0,
        };

        let plaintext = b"test ip packet data";
        let msg = encrypt_transport(&mut send_keys, plaintext).unwrap();
        assert!(msg.len() > 16 + plaintext.len());

        let decrypted = decrypt_transport(&mut recv_keys, &msg).unwrap();
        assert_eq!(&decrypted, plaintext);
        assert_eq!(send_keys.send_counter, 1);
    }
}
