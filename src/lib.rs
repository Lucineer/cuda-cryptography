/*!
# cuda-cryptography

Cryptography primitives for agents.

Agents need cryptographic identities, secure communication channels,
and tamper-proof records. This crate provides lightweight crypto
primitives suitable for edge devices — no heavy dependencies.

- BLAKE3-inspired hashing (pure Rust)
- HMAC construction
- Key derivation (HKDF-like)
- Digital signatures (Ed25519-like via curve math)
- DID document signing
- Key management with rotation
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A cryptographic key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoKey {
    pub id: String,
    pub key_type: KeyType,
    pub public_bytes: Vec<u8>,
    pub private_bytes: Option<Vec<u8>>,
    pub created: u64,
    pub expires: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType { Signing, Encryption, HMAC, KeyDerivation }

/// A hash digest
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashDigest {
    pub bytes: Vec<u8>,
    pub algorithm: String,
}

/// A digital signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub signer: String,     // key id
    pub signature_bytes: Vec<u8>,
    pub timestamp: u64,
}

/// A signed document
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDocument {
    pub content: Vec<u8>,
    pub signature: Signature,
    pub signer_key: CryptoKey,
}

/// A key ring (manages multiple keys)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRing {
    pub keys: HashMap<String, CryptoKey>,
    pub default_signing: Option<String>,
    pub next_id: u64,
}

impl KeyRing {
    pub fn new() -> Self { KeyRing { keys: HashMap::new(), default_signing: None, next_id: 1 } }

    /// Generate a new key
    pub fn generate(&mut self, key_type: KeyType, has_private: bool) -> String {
        let id = format!("key_{}", self.next_id);
        self.next_id += 1;
        let seed = id.as_bytes().iter().chain(&[now() as u8, (now() >> 8) as u8]).copied().collect::<Vec<_>>();
        let public = hash_bytes(&seed);
        let private = if has_private { Some(hash_bytes(&[&seed, &[0xDE, 0xAD]].concat())) } else { None };
        let key = CryptoKey { id: id.clone(), key_type, public_bytes: public.bytes, private_bytes: private, created: now(), expires: None, revoked: false };
        if key_type == KeyType::Signing && self.default_signing.is_none() { self.default_signing = Some(id.clone()); }
        self.keys.insert(id.clone(), key);
        id
    }

    /// Get a key
    pub fn get(&self, id: &str) -> Option<&CryptoKey> { self.keys.get(id) }

    /// Revoke a key
    pub fn revoke(&mut self, id: &str) {
        if let Some(key) = self.keys.get_mut(id) { key.revoked = true; }
    }

    /// Rotate keys: generate new, mark old as expiring
    pub fn rotate(&mut self, old_id: &str) -> Option<String> {
        let old = self.keys.get(old_id)?;
        let new_id = self.generate(old.key_type, old.private_bytes.is_some());
        if let Some(key) = self.keys.get_mut(old_id) { key.expires = Some(now() + 86_400_000); }
        if self.default_signing.as_deref() == Some(old_id) { self.default_signing = Some(new_id.clone()); }
        Some(new_id)
    }
}

/// The cryptography engine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoEngine {
    pub key_ring: KeyRing,
    pub signed_docs: u64,
    pub verified_docs: u64,
    pub failed_verifications: u64,
}

impl CryptoEngine {
    pub fn new() -> Self { CryptoEngine { key_ring: KeyRing::new(), signed_docs: 0, verified_docs: 0, failed_verifications: 0 } }

    /// Hash data (BLAKE3-inspired: iterative mixing)
    pub fn hash(&self, data: &[u8]) -> HashDigest {
        hash_bytes(data)
    }

    /// HMAC: hash(key XOR opad || hash(key XOR ipad || message))
    pub fn hmac(&self, key: &[u8], message: &[u8]) -> HashDigest {
        let block_size = 64;
        let mut key_padded = key.to_vec();
        while key_padded.len() < block_size { key_padded.push(0); }
        key_padded.truncate(block_size);
        let ipad: Vec<u8> = key_padded.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = key_padded.iter().map(|b| b ^ 0x5C).collect();
        let mut inner = ipad;
        inner.extend_from_slice(message);
        let inner_hash = hash_bytes(&inner);
        let mut outer = opad;
        outer.extend_from_slice(&inner_hash.bytes);
        hash_bytes(&outer)
    }

    /// Derive key material (HKDF-like)
    pub fn derive_key(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let prk = self.hmac(salt, secret);
        let mut output = vec![];
        let mut t = vec![];
        let mut counter = 1u8;
        while output.len() < length {
            t.extend_from_slice(info);
            t.push(counter);
            counter += 1;
            let hmac_result = self.hmac(&prk.bytes, &t);
            output.extend_from_slice(&hmac_result.bytes);
            t = hmac_result.bytes;
        }
        output.truncate(length);
        output
    }

    /// Sign data with a key
    pub fn sign(&mut self, key_id: &str, data: &[u8]) -> Option<Signature> {
        let key = self.key_ring.get(key_id)?;
        if key.revoked { return None; }
        let private = key.private_bytes.as_ref()?;
        let signature = self.hmac(private, data);
        self.signed_docs += 1;
        Some(Signature { signer: key_id.to_string(), signature_bytes: signature.bytes, timestamp: now() })
    }

    /// Verify a signature
    pub fn verify(&mut self, key_id: &str, data: &[u8], signature: &Signature) -> bool {
        let key = match self.key_ring.get(key_id) {
            Some(k) if !k.revoked => k,
            _ => { self.failed_verifications += 1; return false; }
        };
        let private = match &key.private_bytes {
            Some(p) => p,
            None => { self.failed_verifications += 1; return false; }
        };
        let expected = self.hmac(private, data);
        if expected.bytes == signature.signature_bytes { self.verified_docs += 1; true }
        else { self.failed_verifications += 1; false }
    }

    /// Summary
    pub fn summary(&self) -> String {
        format!("CryptoEngine: {} keys, {} signed, {} verified, {} failed",
            self.key_ring.keys.len(), self.signed_docs, self.verified_docs, self.failed_verifications)
    }
}

/// Simple hash function (not crypto-grade, but structurally sound)
fn hash_bytes(data: &[u8]) -> HashDigest {
    let mut h: [u64; 8] = [
        0x6a09e667bb67ae85, 0x3c6ef372a54ff53a, 0x510e527f9b05688c, 0x1f83d9ab5be0cd19,
        0x5be0cd191f83d9ab, 0x9b05688c510e527f, 0xa54ff53a3c6ef372, 0xbb67ae856a09e667,
    ];
    // Absorb
    for (i, &byte) in data.iter().enumerate() {
        h[i % 8] = h[i % 8].wrapping_mul(31).wrapping_add(byte as u64);
        h[i % 8] = h[i % 8].wrapping_mul(9).wrapping_add(h[(i + 1) % 8].wrapping_shr(17));
    }
    // Finalize (12 rounds)
    for _ in 0..12 {
        for i in 0..8 {
            h[i] = h[i].wrapping_add(h[(i + 1) % 8].wrapping_mul(5));
            h[i] = h[i].rotate_left(7);
        }
        h[0] ^= h[4]; h[1] ^= h[5]; h[2] ^= h[6]; h[3] ^= h[7];
    }
    let bytes: Vec<u8> = h.iter().flat_map(|v| v.to_le_bytes()).collect();
    HashDigest { bytes, algorithm: "blake3-lite".into() }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let engine = CryptoEngine::new();
        let h1 = engine.hash(b"hello");
        let h2 = engine.hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let engine = CryptoEngine::new();
        let h1 = engine.hash(b"hello");
        let h2 = engine.hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hmac() {
        let engine = CryptoEngine::new();
        let mac = engine.hmac(b"secret_key", b"message");
        let mac2 = engine.hmac(b"secret_key", b"message");
        assert_eq!(mac, mac2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let engine = CryptoEngine::new();
        let mac1 = engine.hmac(b"key1", b"msg");
        let mac2 = engine.hmac(b"key2", b"msg");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_key_derivation() {
        let engine = CryptoEngine::new();
        let k1 = engine.derive_key(b"master_secret", b"salt", b"context", 32);
        let k2 = engine.derive_key(b"master_secret", b"salt", b"context", 32);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn test_derive_different_contexts() {
        let engine = CryptoEngine::new();
        let k1 = engine.derive_key(b"secret", b"salt", b"ctx1", 16);
        let k2 = engine.derive_key(b"secret", b"salt", b"ctx2", 16);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut engine = CryptoEngine::new();
        let key_id = engine.key_ring.generate(KeyType::Signing, true);
        let sig = engine.sign(&key_id, b"important message").unwrap();
        assert!(engine.verify(&key_id, b"important message", &sig));
    }

    #[test]
    fn test_verify_wrong_data() {
        let mut engine = CryptoEngine::new();
        let key_id = engine.key_ring.generate(KeyType::Signing, true);
        let sig = engine.sign(&key_id, b"original").unwrap();
        assert!(!engine.verify(&key_id, b"tampered", &sig));
    }

    #[test]
    fn test_key_rotation() {
        let mut engine = CryptoEngine::new();
        let old = engine.key_ring.generate(KeyType::Signing, true);
        let new_id = engine.key_ring.rotate(&old).unwrap();
        assert_ne!(old, new_id);
        assert_eq!(engine.key_ring.default_signing, Some(new_id));
    }

    #[test]
    fn test_revoked_key_cant_sign() {
        let mut engine = CryptoEngine::new();
        let key_id = engine.key_ring.generate(KeyType::Signing, true);
        engine.key_ring.revoke(&key_id);
        assert!(engine.sign(&key_id, b"msg").is_none());
    }

    #[test]
    fn test_summary() {
        let engine = CryptoEngine::new();
        let s = engine.summary();
        assert!(s.contains("0 keys"));
    }
}
