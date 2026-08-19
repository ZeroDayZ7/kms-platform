// src/domain/keys/repository.rs
use crate::{
    domain::keys::models::{KeyAlgorithm, KeyPairEntity, KeyStatus, ServiceId},
    errors::AppResult,
};

use chrono::DateTime;
use chrono::Utc;
use uuid::Uuid;

pub trait KeyRepository: Send + Sync {
    fn save_key(
        &self,
        key: &KeyPairEntity,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;
    fn get_active_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;
    fn get_key_by_version(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        version: u32,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;
    fn get_all_active_public_keys(
        &self,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;
    fn deactivate_keys_for_service(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    fn update_key_status(
        &self,
        key_id: &Uuid,
        status: KeyStatus,
        deprecated_until: Option<DateTime<Utc>>,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    fn compare_and_set_active_to_deprecated(
        &self,
        key_id: &Uuid,
        deprecated_until: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<bool>> + Send;

    fn get_deprecated_keys_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    fn get_active_or_valid_deprecated_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;

    fn get_all_keys(
        &self,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    fn update_encrypted_key(
        &self,
        key_id: &Uuid,
        encrypted: crate::domain::crypto::EncryptedPrivateKey,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    fn get_keys_needing_rewrap(
        &self,
        current_master_version: i32,
        batch_size: usize,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    fn update_encrypted_keys_batch(
        &self,
        updates: Vec<(Uuid, crate::domain::crypto::EncryptedPrivateKey, i32)>,
    ) -> impl std::future::Future<Output = AppResult<usize>> + Send;
}
