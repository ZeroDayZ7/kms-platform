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

#[derive(Debug, Clone)]
pub struct GeneratedDataKey {
    pub algorithm: KeyAlgorithm,
    pub plaintext: SecretBytes,
    pub wrapped: Vec<u8>,
    pub master_key_version: i32,
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

#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    //#region new
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    //#region as_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    //#region as_mut_bytes
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    //#region into_vec
    pub fn into_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    //#region clone_secret
    pub fn clone_secret(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl fmt::Display for SecretBytes {
    //#region fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Debug for SecretBytes {
    //#region fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(\"")?;
        f.write_str("[REDACTED]")?;
        f.write_str("\")")
    }
}

impl Zeroize for SecretBytes {
    //#region zeroize
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0.clone()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(\"")?;
        f.write_str("[REDACTED]")?;
        f.write_str("\")")
    }
}

impl Zeroize for SecretString {
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
    //#region generate_ed25519_keypair
    fn generate_ed25519_keypair(&self) -> AppResult<RawKeyPair>;
    //#region generate_x25519_keypair
    fn generate_x25519_keypair(&self) -> AppResult<RawKeyPair>;
    //#region generate_symmetric_key
    fn generate_symmetric_key(&self) -> AppResult<RawKeyPair>;
    async fn generate_data_key(&self, algorithm: KeyAlgorithm) -> AppResult<GeneratedDataKey>;
    async fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey>;
    async fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>>;
    //#region current_master_key_version
    async fn current_master_key_version(&self) -> AppResult<i32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_values_are_redacted_in_debug_output() {
        let secret_bytes = SecretBytes::new(b"super-secret-bytes".to_vec());
        let secret_string = SecretString::new("super-secret-string".to_string());

        let bytes_debug = format!("{secret_bytes:?}");
        let string_debug = format!("{secret_string:?}");

        assert!(!bytes_debug.contains("super-secret-bytes"));
        assert!(!string_debug.contains("super-secret-string"));
        assert!(bytes_debug.contains("[REDACTED]"));
        assert!(string_debug.contains("[REDACTED]"));
    }
}
