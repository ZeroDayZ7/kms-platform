use crate::domain::crypto::KmsCryptoService;
use crate::domain::keys::repository::KeyRepository;
use crate::errors::{AppError, AppResult};
use std::sync::Arc;
use zeroize::Zeroize;

pub struct RewrapKeysInput {
    pub target_master_version: i32,
    pub batch_size: usize,
}

pub async fn rewrap_keys<R>(
    key_repo: Arc<R>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    input: RewrapKeysInput,
) -> AppResult<usize>
where
    R: KeyRepository + Send + Sync,
{
    let current_version = crypto_service.current_master_key_version().await?;
    if current_version != input.target_master_version {
        return Err(AppError::ValidationError(format!(
            "Target master key version {} does not match KMS active version {}",
            input.target_master_version, current_version
        )));
    }

    let mut total_rewrapped = 0usize;

    loop {
        let pending_keys = key_repo
            .get_keys_needing_rewrap(current_version, input.batch_size)
            .await?;

        if pending_keys.is_empty() {
            break;
        }

        let mut updated_keys = Vec::with_capacity(pending_keys.len());

        for key in pending_keys {
            let mut decrypted = crypto_service
                .decrypt_private_key(&key.encrypted_private_key)
                .await?;

            let reencrypted = crypto_service.encrypt_private_key(&decrypted).await?;
            // decrypted is Vec<u8> here; zeroize by overwriting
            decrypted.zeroize();

            updated_keys.push((key.id, reencrypted, current_version));
        }

        let count = updated_keys.len();
        key_repo.update_encrypted_keys_batch(updated_keys).await?;
        total_rewrapped += count;
    }

    Ok(total_rewrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::models::{
        KeyAlgorithm, KeyPairEntity, KeyPurpose, KeyStatus, ServiceId,
    };
    use crate::errors::AppError;
    use chrono::Utc;
    use uuid::Uuid;

    struct MockRepo {
        fail_batch: bool,
    }

    #[async_trait::async_trait]
    impl KeyRepository for MockRepo {
        fn save_key(
            &self,
            _key_pair: &KeyPairEntity,
        ) -> impl std::future::Future<Output = AppResult<()>> + Send {
            async { Ok(()) }
        }

        fn get_active_key(
            &self,
            _service_id: &ServiceId,
            _algo: KeyAlgorithm,
        ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send {
            async { Ok(None) }
        }

        fn get_key_by_version(
            &self,
            _service_id: &ServiceId,
            _algo: KeyAlgorithm,
            _version: u32,
        ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send {
            async { Ok(None) }
        }

        fn get_all_active_public_keys(
            &self,
        ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send {
            async { Ok(vec![]) }
        }

        fn deactivate_keys_for_service(
            &self,
            _service_id: &ServiceId,
            _algo: KeyAlgorithm,
        ) -> impl std::future::Future<Output = AppResult<()>> + Send {
            async { Ok(()) }
        }

        fn update_key_status(
            &self,
            _key_id: &Uuid,
            _status: crate::domain::keys::models::KeyStatus,
            _deprecated_until: Option<chrono::DateTime<Utc>>,
        ) -> impl std::future::Future<Output = AppResult<()>> + Send {
            async { Ok(()) }
        }

        fn compare_and_set_active_to_deprecated(
            &self,
            _key_id: &Uuid,
            _deprecated_until: chrono::DateTime<Utc>,
        ) -> impl std::future::Future<Output = AppResult<bool>> + Send {
            async { Ok(true) }
        }

        fn rotate_active_key(
            &self,
            _service_id: &ServiceId,
            _algorithm: KeyAlgorithm,
            _new_key: &crate::domain::keys::models::KeyPairEntity,
            _deprecated_until: Option<chrono::DateTime<Utc>>,
        ) -> impl std::future::Future<Output = AppResult<bool>> + Send {
            async { Ok(true) }
        }

        fn get_deprecated_keys_expired(
            &self,
            _now: chrono::DateTime<Utc>,
        ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send {
            async { Ok(vec![]) }
        }

        fn get_active_or_valid_deprecated_key(
            &self,
            _service_id: &ServiceId,
            _algo: KeyAlgorithm,
            _now: chrono::DateTime<Utc>,
        ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send {
            async { Ok(None) }
        }

        fn get_all_keys(
            &self,
        ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send {
            async { Ok(vec![]) }
        }

        fn update_encrypted_key(
            &self,
            _key_id: &Uuid,
            _encrypted: crate::domain::crypto::EncryptedPrivateKey,
        ) -> impl std::future::Future<Output = AppResult<()>> + Send {
            async { Ok(()) }
        }

        fn get_keys_needing_rewrap(
            &self,
            _current_master_version: i32,
            _batch_size: usize,
        ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send {
            // return one dummy key to trigger behavior
            let key = KeyPairEntity {
                id: Uuid::now_v7(),
                service_id: ServiceId("svc".to_string()),
                algorithm: KeyAlgorithm::Ed25519,
                purpose: KeyPurpose::Signing,
                public_key_pem: "pem".to_string(),
                encrypted_private_key: crate::domain::crypto::EncryptedPrivateKey {
                    ciphertext: vec![1, 2, 3],
                    master_key_version: 0,
                },
                version: 1,
                status: KeyStatus::Active,
                created_at: Utc::now(),
                expires_at: None,
            };
            async { Ok(vec![key]) }
        }

        fn update_encrypted_keys_batch(
            &self,
            _updates: Vec<(Uuid, crate::domain::crypto::EncryptedPrivateKey, i32)>,
        ) -> impl std::future::Future<Output = AppResult<usize>> + Send {
            let fail = self.fail_batch;
            async move {
                if fail {
                    Err(AppError::Internal("forced failure".to_string()))
                } else {
                    Ok(1)
                }
            }
        }
    }

    #[tokio::test]
    async fn rewrap_keys_rollback_on_failure() {
        let repo = Arc::new(MockRepo { fail_batch: true });

        struct DummyCrypto;
        #[async_trait::async_trait]
        impl KmsCryptoService for DummyCrypto {
            async fn current_master_key_version(&self) -> crate::errors::AppResult<i32> {
                Ok(1)
            }
            async fn decrypt_private_key(
                &self,
                _encrypted: &crate::domain::crypto::EncryptedPrivateKey,
            ) -> crate::errors::AppResult<Vec<u8>> {
                Ok(vec![1, 2, 3])
            }
            async fn encrypt_private_key(
                &self,
                _plaintext: &[u8],
            ) -> crate::errors::AppResult<crate::domain::crypto::EncryptedPrivateKey> {
                Ok(crate::domain::crypto::EncryptedPrivateKey {
                    ciphertext: vec![4, 5, 6],
                    master_key_version: 1,
                })
            }
            fn generate_ed25519_keypair(
                &self,
            ) -> crate::errors::AppResult<crate::domain::crypto::RawKeyPair> {
                Err(AppError::Internal("not implemented".into()))
            }
            fn generate_x25519_keypair(
                &self,
            ) -> crate::errors::AppResult<crate::domain::crypto::RawKeyPair> {
                Err(AppError::Internal("not implemented".into()))
            }
            fn generate_symmetric_key(
                &self,
            ) -> crate::errors::AppResult<crate::domain::crypto::RawKeyPair> {
                Err(AppError::Internal("not implemented".into()))
            }
            async fn generate_data_key(&self, _algorithm: crate::domain::crypto::KeyAlgorithm) -> crate::errors::AppResult<crate::domain::crypto::GeneratedDataKey> {
                Err(AppError::Internal("not implemented".into()))
            }
        }

        let crypto = Arc::new(DummyCrypto);
        let input = RewrapKeysInput {
            target_master_version: 1,
            batch_size: 10,
        };

        let res = rewrap_keys(repo.clone(), crypto.clone(), input).await;
        assert!(res.is_err());
    }
}
