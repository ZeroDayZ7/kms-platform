// src/application/use_cases/get_public_key.rs
use std::sync::Arc;

use crate::{
    domain::keys::{
        models::{KeyAlgorithm, KeyPairEntity, ServiceId},
        repository::KeyRepository,
    },
    errors::{AppError, AppResult},
};

pub struct GetPublicKeyInput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
}

pub struct GetPublicKeyUseCase<R>
where
    R: KeyRepository + Send + Sync,
{
    key_repo: Arc<R>,
}

impl<R> GetPublicKeyUseCase<R>
where
    R: KeyRepository + Send + Sync,
{
    //#region new
    pub fn new(key_repo: Arc<R>) -> Self {
        Self { key_repo }
    }

    pub async fn execute(&self, input: GetPublicKeyInput) -> AppResult<KeyPairEntity> {
        let now = chrono::Utc::now();
        let key = self
            .key_repo
            .get_active_or_valid_deprecated_key(&input.service_id, input.algorithm, now)
            .await?;

        match key {
            Some(k) => Ok(k),
            None => Err(AppError::NotFound(format!(
                "No active or valid deprecated public key found for service '{}' with algorithm '{:?}'",
                input.service_id.0, input.algorithm
            ))),
        }
    }
}
