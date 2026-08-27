use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tokio::fs;

// Importujemy EncryptedContainer z kms-core
use kms_core::crypto::aes::EncryptedContainer;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareFileRecord {
    pub index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub container: EncryptedContainer,
    pub share_sha256: String,
    pub created_at: DateTime<Utc>,
}

//#region compute_sha256_hex
pub fn compute_sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

//#region write_share_file
pub async fn write_share_file(
    dir: &Path,
    index: u8,
    threshold: u8,
    total_shares: u8,
    container: EncryptedContainer,
) -> Result<PathBuf> {
    let file_path = dir.join(format!("share_{index}.json"));
    let created_at = Utc::now();

    let container_json = serde_json::to_string(&container)?;
    let sha256 = compute_sha256_hex(&container_json);

    let record = ShareFileRecord {
        index,
        threshold,
        total_shares,
        container,
        share_sha256: sha256,
        created_at,
    };

    let json = serde_json::to_string_pretty(&record)?;
    fs::write(&file_path, json)
        .await
        .with_context(|| format!("Failed to write share file {}", file_path.display()))?;

    Ok(file_path)
}

#[allow(dead_code)]
//#region load_share_directory
pub async fn load_share_directory(dir: &Path) -> Result<Vec<ShareFileRecord>> {
    let mut records = Vec::new();
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }

        let content = fs::read_to_string(&path).await?;
        let record: ShareFileRecord = serde_json::from_str(&content)
            .with_context(|| format!("Uszkodzona struktura JSON w pliku: {}", path.display()))?;

        // --- WERYFIKACJA HASHA SHA-256 ---
        let container_json = serde_json::to_string(&record.container)?;
        let expected_sha256 = compute_sha256_hex(&container_json);

        let record_bytes = record.share_sha256.as_bytes();
        let expected_bytes = expected_sha256.as_bytes();

        if record_bytes.len() != expected_bytes.len()
            || record_bytes.ct_eq(expected_bytes).unwrap_u8() == 0
        {
            anyhow::bail!(
                "Błąd integralności! Plik {} został zmodyfikowany lub uszkodzony (niezgodny hash SHA-256).",
                path.display()
            );
        }

        records.push(record);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    #[test]
    fn constant_time_compare_behaves() {
        let a = "abcdef0123456789".to_string();
        let b = "abcdef0123456789".to_string();
        let c = "abcdef0123456780".to_string();

        assert_eq!(a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8(), 1u8);
        assert_eq!(a.as_bytes().ct_eq(c.as_bytes()).unwrap_u8(), 0u8);
    }
}