use crate::errors::AppResult;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

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
    pub nonce: Vec<u8>,
    pub master_key_version: i32,
}

#[derive(ZeroizeOnDrop)]
pub struct RawKeyPair {
    pub public_key_pem: String,
    pub private_key_bytes: Vec<u8>,
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
