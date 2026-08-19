use kms_core::ceremony::{CeremonyManifest, ShareFileRecord, compute_share_sha256};
use kms_core::crypto::aes::{EncryptedContainer, decrypt_storage_key};
use kms_core::crypto::keys::SecretKey as CoreSecretKey;
use kms_core::crypto::sss::combine_shares;
use std::{fs, path::Path, sync::Arc};
use tracing::{info, warn};

use crate::{
    config::acl::AclSettings,
    domain::{
        crypto::KmsCryptoService,
        keys::{
            models::{KeyAlgorithm, KeyPairEntity, KeyPurpose, KeyStatus},
            repository::KeyRepository,
        },
    },
    errors::{AppError, AppResult},
};

pub type SecureStorageKey = CoreSecretKey;

fn validate_share_record(record: &ShareFileRecord, manifest: &CeremonyManifest) -> AppResult<()> {
    if record.index == 0 || record.index > manifest.total_shares {
        return Err(AppError::ValidationError(format!(
            "Share index {} is outside the valid range 1..{}",
            record.index, manifest.total_shares
        )));
    }

    if record.threshold != manifest.threshold {
        return Err(AppError::ValidationError(format!(
            "Share threshold mismatch: record {} != manifest {}",
            record.threshold, manifest.threshold
        )));
    }

    if record.total_shares != manifest.total_shares {
        return Err(AppError::ValidationError(format!(
            "Total share mismatch: record {} != manifest {}",
            record.total_shares, manifest.total_shares
        )));
    }

    let computed_hash = compute_share_sha256(&record.share_hex);
    if computed_hash != record.share_sha256 {
        return Err(AppError::ValidationError(format!(
            "Share SHA-256 mismatch for share index {}",
            record.index
        )));
    }

    Ok(())
}

fn read_share_file(path: &Path) -> AppResult<ShareFileRecord> {
    let content = fs::read_to_string(path).map_err(|err| {
        AppError::RuntimeError(format!(
            "Failed to read share file {}: {err}",
            path.display()
        ))
    })?;

    let record: ShareFileRecord =
        serde_json::from_str(&content).map_err(AppError::SerializationError)?;

    Ok(record)
}

pub fn recover_storage_key_from_ceremony(
    manifest_path: impl AsRef<Path>,
    share_dir: impl AsRef<Path>,
) -> AppResult<SecureStorageKey> {
    let manifest_path = manifest_path.as_ref();
    let share_dir = share_dir.as_ref();

    let manifest_content = fs::read_to_string(manifest_path).map_err(|err| {
        AppError::RuntimeError(format!(
            "Failed to read ceremony manifest {}: {err}",
            manifest_path.display()
        ))
    })?;

    let manifest: CeremonyManifest =
        serde_json::from_str(&manifest_content).map_err(AppError::SerializationError)?;

    let mut selected_shares = Vec::new();
    for file_name in &manifest.share_files {
        let path = share_dir.join(file_name);
        if !path.exists() {
            return Err(AppError::NotFound(format!(
                "Share file {} referenced by manifest is missing",
                path.display()
            )));
        }

        let record = read_share_file(&path)?;
        validate_share_record(&record, &manifest)?;

        selected_shares.push((record.index, record.share_hex.clone()));
    }

    if selected_shares.len() < manifest.threshold as usize {
        return Err(AppError::ValidationError(format!(
            "Need at least {} shares, got {}",
            manifest.threshold,
            selected_shares.len()
        )));
    }

    let selected_secret_shares: Vec<kms_core::crypto::sss::SecretShare> = selected_shares[..manifest.threshold as usize]
        .iter()
        .map(|(index, value)| kms_core::crypto::sss::SecretShare {
            index: *index,
            value: value.clone(),
        })
        .collect();

    let recovered_bytes = combine_shares(&selected_secret_shares).map_err(|err| {
        AppError::CryptoError(format!(
            "Failed to reconstruct master key from shares: {err}"
        ))
    })?;

    let mut master_key_bytes = [0u8; 32];
    master_key_bytes.copy_from_slice(&recovered_bytes);
    let master_key = CoreSecretKey::from_bytes(master_key_bytes);

    let container = EncryptedContainer {
        nonce: manifest.encrypted_storage_key_nonce.clone(),
        ciphertext: manifest.encrypted_storage_key_ciphertext.clone(),
    };

    let storage_key = decrypt_storage_key(&master_key, &container)
        .map_err(|err| AppError::CryptoError(format!("Failed to decrypt storage key: {err}")))?;

    Ok(storage_key)
}

/// Recover storage key by using shares provided directly (e.g. via HTTP request).
pub fn recover_storage_key_from_shares(
    manifest_path: impl AsRef<Path>,
    shares: &[String],
) -> AppResult<SecureStorageKey> {
    let manifest_path = manifest_path.as_ref();

    let manifest_content = fs::read_to_string(manifest_path).map_err(|err| {
        AppError::RuntimeError(format!(
            "Failed to read ceremony manifest {}: {err}",
            manifest_path.display()
        ))
    })?;

    let manifest: CeremonyManifest =
        serde_json::from_str(&manifest_content).map_err(AppError::SerializationError)?;

    if shares.len() < manifest.threshold as usize {
        return Err(AppError::ValidationError(format!(
            "Need at least {} shares, got {}",
            manifest.threshold,
            shares.len()
        )));
    }

    // Convert provided share strings into (index, value) tuples expected by combine_shares
    let share_tuples: Vec<(u8, String)> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| ((i as u8) + 1, s.clone()))
        .collect();

    let selected_secret_shares: Vec<kms_core::crypto::sss::SecretShare> = share_tuples[..manifest.threshold as usize]
        .iter()
        .map(|(index, value)| kms_core::crypto::sss::SecretShare {
            index: *index,
            value: value.clone(),
        })
        .collect();

    let recovered_bytes = combine_shares(&selected_secret_shares).map_err(|err| {
        AppError::CryptoError(format!(
            "Failed to reconstruct master key from shares: {err}"
        ))
    })?;

    let mut master_key_bytes = [0u8; 32];
    master_key_bytes.copy_from_slice(&recovered_bytes);
    let master_key = CoreSecretKey::from_bytes(master_key_bytes);

    let container = EncryptedContainer {
        nonce: manifest.encrypted_storage_key_nonce.clone(),
        ciphertext: manifest.encrypted_storage_key_ciphertext.clone(),
    };

    let storage_key = decrypt_storage_key(&master_key, &container)
        .map_err(|err| AppError::CryptoError(format!("Failed to decrypt storage key: {err}")))?;

    Ok(storage_key)
}

pub async fn bootstrap_keys<R>(
    acl_settings: &AclSettings,
    key_repo: Arc<R>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
) -> AppResult<()>
where
    R: KeyRepository,
{
    info!("Rozpoczynanie weryfikacji i bootstrapu kluczy z konfiguracji ACL...");

    for service_cfg in acl_settings.services.values() {
        for rule in &service_cfg.allowed_access {
            let target_service = rule.target_service.clone();
            let algorithm = rule.algorithm;

            let existing_key = key_repo.get_active_key(&target_service, algorithm).await?;

            if existing_key.is_none() {
                warn!(
                    service = %target_service.0,
                    alg = ?algorithm,
                    "Brak aktywnego klucza w MongoDB. Generowanie nowego klucza..."
                );

                let (generated_key, purpose) = match algorithm {
                    KeyAlgorithm::Ed25519 => (
                        crypto_service.generate_ed25519_keypair()?,
                        KeyPurpose::Signing,
                    ),
                    KeyAlgorithm::X25519 => (
                        crypto_service.generate_x25519_keypair()?,
                        KeyPurpose::Encryption,
                    ),
                    KeyAlgorithm::AES256GCM => (
                        crypto_service.generate_symmetric_key()?,
                        KeyPurpose::Encryption,
                    ),
                    KeyAlgorithm::HmacSha256 => (
                        crypto_service.generate_symmetric_key()?,
                        KeyPurpose::Authentication,
                    ),
                };

                let encrypted_private_key =
                    crypto_service.encrypt_private_key(&generated_key.private_key_bytes)?;

                let new_key = KeyPairEntity {
                    id: uuid::Uuid::now_v7(),
                    service_id: target_service.clone(),
                    algorithm,
                    purpose,
                    public_key_pem: generated_key.public_key_pem.clone(),
                    encrypted_private_key,
                    version: 1,
                    status: KeyStatus::Active,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                };

                key_repo.save_key(&new_key).await?;
                info!(
                    service = %target_service.0,
                    alg = ?algorithm,
                    "Pomyślnie utworzono i zaszyfrowano klucz w MongoDB."
                );
            }
        }
    }

    info!("Bootstrap kluczy zakończony sukcesem.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn ceremony_bootstrap_reconstructs_storage_key_from_manifest_and_shares() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("ceremony_manifest.json");
        let share_dir = dir.path().join("shares");
        fs::create_dir_all(&share_dir).unwrap();

        let master_key = [42u8; 32];
        let storage_key = [7u8; 32];

        let shares = ssss::gen_shares(
            &ssss::SsssConfig::builder()
                .num_shares(5)
                .threshold(3)
                .build(),
            &master_key,
        )
        .unwrap();

        for (idx, share_hex) in shares.iter().take(3).enumerate() {
            let share_record = ShareFileRecord {
                index: (idx as u8) + 1,
                threshold: 3,
                total_shares: 5,
                share_hex: share_hex.clone(),
                share_sha256: compute_share_sha256(share_hex),
                created_at: Utc::now(),
            };

            let path = share_dir.join(format!("share_{}.json", idx + 1));
            fs::write(path, serde_json::to_string_pretty(&share_record).unwrap()).unwrap();
        }

        let nonce = [1u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&master_key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), &storage_key[..])
            .unwrap();

        let manifest = CeremonyManifest {
            id: Uuid::new_v4(),
            version: 1,
            created_at: Utc::now(),
            threshold: 3,
            total_shares: 5,
            share_files: vec![
                "share_1.json".to_string(),
                "share_2.json".to_string(),
                "share_3.json".to_string(),
            ],
            encrypted_storage_key_nonce: hex::encode(nonce),
            encrypted_storage_key_ciphertext: hex::encode(ciphertext),
        };

        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let restored = recover_storage_key_from_ceremony(&manifest_path, &share_dir).unwrap();
        assert_eq!(restored.as_bytes(), &storage_key);
    }
}
