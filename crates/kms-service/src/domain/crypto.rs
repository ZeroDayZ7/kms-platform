use crate::errors::AppResult;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    X25519,
    AES256GCM,
    HmacSha256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyPurpose {
    Signing,
    Encryption,
    Authentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    pub ciphertext: Vec<u8>,
    pub master_key_version: i32,
}

#[derive(ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn into_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn clone_secret(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(\"")?;
        f.write_str("[REDACTED]")?;
        f.write_str("\")")
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(ZeroizeOnDrop)]
pub struct RawKeyPair {
    pub public_key_pem: String,
    pub private_key_bytes: SecretBytes,
}

#[async_trait::async_trait]
pub trait KmsCryptoService: Send + Sync {
    fn generate_ed25519_keypair(&self) -> AppResult<RawKeyPair>;
    fn generate_x25519_keypair(&self) -> AppResult<RawKeyPair>;
    fn generate_symmetric_key(&self) -> AppResult<RawKeyPair>;
    async fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey>;
    async fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>>;
    fn current_master_key_version(&self) -> i32;
}
