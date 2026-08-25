use crate::crypto::aes::EncryptedContainer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyManifest {
    pub id: uuid::Uuid,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_files: Vec<String>,
    pub encrypted_storage_key_nonce: String,
    pub encrypted_storage_key_ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFileRecord {
    pub index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub container: EncryptedContainer,
    pub share_sha256: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

//#region compute_share_sha256
pub fn compute_share_sha256(share_hex: &str) -> String {
    let mut hasher = Sha256::new();

    if !share_hex.len().is_multiple_of(2) {
        let normalized = format!("0{share_hex}");
        hasher.update(normalized.as_bytes());
    } else {
        hasher.update(share_hex.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}
