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
    let current_version = crypto_service.current_master_key_version();
    if current_version != input.target_master_version {
        return Err(AppError::ValidationError(format!(
            "Target master key version {} does not match KMS active version {}",
            input.target_master_version, current_version
        )));
    }

    let mut total_rewrapped = 0;

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
            decrypted.zeroize();

            updated_keys.push((key.id, reencrypted, current_version));
        }

        let count = updated_keys.len();
        key_repo.update_encrypted_keys_batch(updated_keys).await?;
        total_rewrapped += count;
    }

    Ok(total_rewrapped)
}
