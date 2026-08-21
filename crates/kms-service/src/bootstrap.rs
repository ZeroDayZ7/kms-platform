use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

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

/// Sprawdza w pętli dostępność i stan odblokowania (unseal) vHSM przed podjęciem operacji bootstrapu
pub async fn wait_for_vhsm_unsealed(socket_path: &str) -> anyhow::Result<()> {
    info!(
        "🔍 Sprawdzanie dostępności i stanu vHSM na gnieździe: {}",
        socket_path
    );

    loop {
        let test_req = HsmRequest::Encrypt {
            key_id: "master_key".to_string(),
            key_version: None,
            plaintext: b"healthcheck".to_vec(),
        };

        match send_hsm_request(socket_path, &test_req).await {
            Ok(HsmResponse::Encrypted { .. }) => {
                info!("✅ vHSM jest podłączony i ODBLOKOWANY (Unsealed). Kontynuacja startu...");
                return Ok(());
            }
            Ok(HsmResponse::Error { code, message }) => {
                warn!(
                    "⏳ vHSM jest podłączony, ale ZABLOKOWANY (Sealed) lub niezainicjalizowany. Kod: {}, Wiadomość: '{}'. Oczekiwanie na Unseal via CLI...",
                    code, message
                );
            }
            Err(err) => {
                warn!(
                    "⏳ Brak połączenia z gniazdem vHSM ({}) [{}]. Oczekiwanie na uruchomienie daemona...",
                    socket_path, err
                );
            }
            _ => {
                warn!("⏳ Otrzymano nieoczekiwaną odpowiedź z vHSM. Ponawianie próby...");
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn bootstrap_keys<R>(
    acl_settings: &AclSettings,
    key_repo: Arc<R>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    key_cache: Arc<crate::server::state::KeyCache>,
) -> AppResult<()>
where
    R: KeyRepository,
{
    info!("Rozpoczynanie weryfikacji i bootstrapu kluczy z konfiguracji ACL...");

    for service_cfg in acl_settings.services.values() {
        for rule in &service_cfg.allowed_access {
            let target_service = rule.target_service.clone();
            let algorithm = rule.algorithm;

            // 1. Sprawdź lub utwórz w PostgreSQL (Zawsze!)
            let existing_key = key_repo.get_active_key(&target_service, algorithm).await?;
            let active_key = match existing_key {
                Some(key) => key,
                None => {
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

                    let encrypted_private_key = crypto_service
                        .encrypt_private_key(&generated_key.private_key_bytes)
                        .await?;

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
                        "Brak aktywnego klucza w PostgreSQL. Generowanie nowego..."
                    );
                    
                    // Generowanie i zapis do PostgreSQL
                    let new_key = generate_and_save_key(
                        &target_service, 
                        algorithm, 
                        crypto_service.as_ref(), 
                        key_repo.as_ref()
                    ).await?;

                    new_key
                }
            };

            // 2. Ładuj do RAM tylko wtedy, gdy preload == true
            if rule.preload {
            let private_key = crypto_service
                .decrypt_private_key(&active_key.encrypted_private_key)
                    .await?;

            key_cache.insert(&target_service, algorithm, active_key.version, private_key);
            info!(
                service = %target_service.0,
                alg = ?algorithm,
                    "✅ Klucz preloaded do KeyCache (RAM)."
            );
            }
        }
    }

    info!("Bootstrap kluczy zakończony sukcesem.");
    Ok(())
}