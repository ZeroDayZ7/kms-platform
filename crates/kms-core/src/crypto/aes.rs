use crate::crypto::keys::{KEY_SIZE, SecretKey};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use getrandom::getrandom;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedContainer {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn encrypt_storage_key(
    master_key: &SecretKey,
    storage_key: &SecretKey,
) -> Result<EncryptedContainer> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())?;

    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, storage_key.as_bytes().as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(EncryptedContainer {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn decrypt_storage_key(
    master_key: &SecretKey,
    container: &EncryptedContainer,
) -> Result<SecretKey> {
    let cipher =
        Aes256Gcm::new_from_slice(master_key.as_bytes()).map_err(|e| anyhow!(e.to_string()))?;

    let nonce_bytes = hex::decode(&container.nonce).map_err(|e| anyhow!(e.to_string()))?;
    let ciphertext_bytes =
        hex::decode(&container.ciphertext).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    if decrypted_bytes.len() != KEY_SIZE {
        decrypted_bytes.zeroize();
        return Err(anyhow!("Invalid key length recovered"));
    }

    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&decrypted_bytes);
    decrypted_bytes.zeroize();

    Ok(SecretKey::from_bytes(out))
}
