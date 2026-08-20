use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareFileRecord {
    pub index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_hex: String,
    pub share_sha256: String,
    pub created_at: DateTime<Utc>,
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

#[allow(dead_code)]
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
        let record: ShareFileRecord = serde_json::from_str(&content)
            .with_context(|| format!("Uszkodzona struktura JSON w pliku: {}", path.display()))?;

        // --- WERYFIKACJA HASHA SHA-256 ---
        let expected_sha256 = compute_sha256_hex(&record.share_hex);
        if record.share_sha256 != expected_sha256 {
            anyhow::bail!(
                "Błąd integralności! Plik {} został zmodyfikowany lub uszkodzony (niezgodny hash SHA-256).",
                path.display()
            );
        }

        records.push(record);
    }
    Ok(records)
}