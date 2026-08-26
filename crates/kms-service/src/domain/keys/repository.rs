// src/domain/keys/repository.rs
use crate::{
    domain::keys::models::{KeyAlgorithm, KeyPairEntity, KeyStatus, ServiceId},
    errors::AppResult,
};

use chrono::DateTime;
use chrono::Utc;
use uuid::Uuid;

pub trait KeyRepository: Send + Sync {
    //#region save_key
    fn save_key(
        &self,
        key: &KeyPairEntity,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;
    //#region get_active_key
    fn get_active_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;
    //#region get_key_by_version
    fn get_key_by_version(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        version: u32,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;
    //#region get_all_active_public_keys
    fn get_all_active_public_keys(
        &self,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;
    //#region deactivate_keys_for_service
    fn deactivate_keys_for_service(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    //#region update_key_status
    fn update_key_status(
        &self,
        key_id: &Uuid,
        status: KeyStatus,
        deprecated_until: Option<DateTime<Utc>>,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    //#region compare_and_set_active_to_deprecated
    fn compare_and_set_active_to_deprecated(
        &self,
        key_id: &Uuid,
        deprecated_until: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<bool>> + Send;

    //#region rotate_active_key
    fn rotate_active_key(
        &self,
        service_id: &ServiceId,
        algorithm: KeyAlgorithm,
        new_key: &crate::domain::keys::models::KeyPairEntity,
        deprecated_until: Option<DateTime<Utc>>,
    ) -> impl std::future::Future<Output = AppResult<bool>> + Send;

    //#region get_deprecated_keys_expired
    fn get_deprecated_keys_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    //#region get_active_or_valid_deprecated_key
    fn get_active_or_valid_deprecated_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = AppResult<Option<KeyPairEntity>>> + Send;

    //#region get_all_keys
    fn get_all_keys(
        &self,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    //#region update_encrypted_key
    fn update_encrypted_key(
        &self,
        key_id: &Uuid,
        encrypted: crate::domain::crypto::EncryptedPrivateKey,
    ) -> impl std::future::Future<Output = AppResult<()>> + Send;

    //#region get_keys_needing_rewrap
    fn get_keys_needing_rewrap(
        &self,
        current_master_version: i32,
        batch_size: usize,
    ) -> impl std::future::Future<Output = AppResult<Vec<KeyPairEntity>>> + Send;

    //#region update_encrypted_keys_batch
    fn update_encrypted_keys_batch(
        &self,
        updates: Vec<(Uuid, crate::domain::crypto::EncryptedPrivateKey, i32)>,
    ) -> impl std::future::Future<Output = AppResult<usize>> + Send;
}
