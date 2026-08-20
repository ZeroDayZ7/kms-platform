use std::sync::Arc;
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
    errors::AppResult,
};

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