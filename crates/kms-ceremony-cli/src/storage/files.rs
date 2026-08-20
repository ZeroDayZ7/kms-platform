use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::crypto::keys::{KEY_SIZE, SecretKey};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareFileRecord {
    pub index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_hex: String,
    pub share_sha256: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CeremonyManifest {
    pub id: Uuid,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_files: Vec<String>,
    pub encrypted_storage_key_nonce: String,
    pub encrypted_storage_key_ciphertext: String,
}

pub fn compute_sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn write_share_file(
    dir: &Path,
    index: u8,
    threshold: u8,
    total_shares: u8,
    share_hex: String,
) -> Result<PathBuf> {
    let file_path = dir.join(format!("share_{index}.json"));
    let created_at = Utc::now();
    let sha256 = compute_sha256_hex(&share_hex);

    let record = ShareFileRecord {
        index,
        threshold,
        total_shares,
        share_hex: share_hex.clone(),
        share_sha256: sha256,
        created_at,
    };

    let json = serde_json::to_string_pretty(&record)?;
    fs::write(&file_path, json)
        .with_context(|| format!("Failed to write share file {}", file_path.display()))?;

    Ok(file_path)
}

pub fn write_manifest(
    output_dir: &Path,
    total_shares: u8,
    threshold: u8,
    share_files: &[String],
    storage_nonce: String,
    storage_ciphertext: String,
) -> Result<()> {
    let manifest = CeremonyManifest {
        id: Uuid::new_v4(),
        version: 1,
        created_at: Utc::now(),
        threshold,
        total_shares,
        share_files: share_files.to_vec(),
        encrypted_storage_key_nonce: storage_nonce,
        encrypted_storage_key_ciphertext: storage_ciphertext,
    };

    let manifest_path = output_dir.join("ceremony_manifest.json");
    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, json).with_context(|| {
        format!(
            "Failed to write ceremony manifest {}",
            manifest_path.display()
        )
    })?;

    Ok(())
}

pub fn load_share_directory(dir: &Path) -> Result<Vec<ShareFileRecord>> {
    let mut records = Vec::new();
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }

        let content = fs::read_to_string(&path)?;
        let record: ShareFileRecord = serde_json::from_str(&content)?;
        records.push(record);
    }
    Ok(records)
}

pub fn write_master_key_file(path: &Path, key: &SecretKey) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }

    let hex = hex::encode(key.as_bytes());
    let key_bytes = format!("{hex}\n");
    fs::write(path, key_bytes)?;
    Ok(())
}

#[allow(dead_code)]
pub fn read_master_key_file(path: &Path) -> Result<[u8; KEY_SIZE]> {
    let raw = fs::read_to_string(path)?;
    let cleaned = raw.trim();
    let decoded = hex::decode(cleaned)?;
    if decoded.len() != KEY_SIZE {
        anyhow::bail!("Recovered key file does not contain exactly 32 bytes");
    }
    let mut result = [0u8; KEY_SIZE];
    result.copy_from_slice(&decoded);
    Ok(result)
}
