use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_SIZE]);

impl SecretKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedContainer {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn generate_master_key() -> SecretKey {
    SecretKey::generate()
}

pub fn encrypt_storage_key(
    master_key: &SecretKey,
    storage_key: &SecretKey,
) -> anyhow::Result<EncryptedContainer> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to initialize cipher: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, storage_key.as_bytes().as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    Ok(EncryptedContainer {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

#[allow(dead_code)]
pub fn decrypt_storage_key(
    master_key: &SecretKey,
    container: &EncryptedContainer,
) -> anyhow::Result<SecretKey> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to initialize cipher: {e}"))?;

    let nonce_bytes = hex::decode(&container.nonce)?;
    let ciphertext_bytes = hex::decode(&container.ciphertext)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    if decrypted_bytes.len() != KEY_SIZE {
        decrypted_bytes.zeroize();
        anyhow::bail!("Invalid key length recovered");
    }

    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&decrypted_bytes);
    decrypted_bytes.zeroize();

    Ok(SecretKey::from_bytes(key_arr))
}