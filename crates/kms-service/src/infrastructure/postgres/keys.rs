use chrono::{DateTime, Utc};
use kms_db::repositories::{KeyDbRow, KeyQueries};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    domain::{
        crypto::{EncryptedPrivateKey, KeyAlgorithm},
        keys::{
            models::{KeyPairEntity, KeyPurpose, KeyStatus, ServiceId},
            repository::KeyRepository,
        },
    },
    errors::{AppError, AppResult},
};

pub struct PgKeyRepository {
    pool: PgPool,
}

impl PgKeyRepository {
    //#region new
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl KeyRepository for PgKeyRepository {
    async fn save_key(&self, key_pair: &KeyPairEntity) -> AppResult<()> {
        let status = format!("{:?}", key_pair.status)
            .replace("Deprecated { valid_until: ... }", "Deprecated");
        let is_active = matches!(key_pair.status, KeyStatus::Active);

        KeyQueries::save_key(
            &self.pool,
            key_pair.id,
            &key_pair.service_id.0,
            &format!("{:?}", key_pair.algorithm),
            key_pair.version,
            &key_pair.encrypted_private_key.ciphertext,
            &key_pair.public_key_pem,
            &format!("{:?}", key_pair.purpose),
            &status,
            is_active,
        )
        .await
        .map_err(AppError::from)?;

        Ok(())
    }

    async fn get_active_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> AppResult<Option<KeyPairEntity>> {
        let row = KeyQueries::get_active_key(&self.pool, &service_id.0, &format!("{:?}", algo))
            .await
            .map_err(AppError::from)?;

        match row {
            Some(r) => Ok(Some(map_key_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_key_by_version(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        version: u32,
    ) -> AppResult<Option<KeyPairEntity>> {
        let row = KeyQueries::get_key_by_version(
            &self.pool,
            &service_id.0,
            &format!("{:?}", algo),
            version,
        )
        .await
        .map_err(AppError::from)?;

        match row {
            Some(r) => Ok(Some(map_key_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_all_active_public_keys(&self) -> AppResult<Vec<KeyPairEntity>> {
        let rows = KeyQueries::get_all_active_public_keys(&self.pool)
            .await
            .map_err(AppError::from)?;

        rows.into_iter().map(map_key_row).collect()
    }

    async fn get_all_active_keys(&self) -> AppResult<Vec<KeyPairEntity>> {
        let rows = KeyQueries::get_all_active_keys(&self.pool)
            .await
            .map_err(AppError::from)?;

        rows.into_iter().map(map_key_row).collect()
    }

    async fn deactivate_keys_for_service(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> AppResult<()> {
        KeyQueries::deactivate_keys_for_service(&self.pool, &service_id.0, &format!("{:?}", algo))
            .await
            .map_err(AppError::from)?;
        Ok(())
    }

    async fn update_key_status(
        &self,
        key_id: &Uuid,
        status: KeyStatus,
        deprecated_until: Option<DateTime<Utc>>,
    ) -> AppResult<()> {
        let status_str = match status {
            KeyStatus::Active => "Active",
            KeyStatus::Deprecated { .. } => "Deprecated",
            KeyStatus::Revoked => "Revoked",
            KeyStatus::Expired => "Expired",
            KeyStatus::Compromised => "Compromised",
        };
        let is_active = matches!(status, KeyStatus::Active);
        let _ = deprecated_until;

        KeyQueries::update_key_status(&self.pool, *key_id, status_str, is_active)
            .await
            .map_err(AppError::from)?;

        Ok(())
    }

    async fn compare_and_set_active_to_deprecated(
        &self,
        key_id: &Uuid,
        deprecated_until: DateTime<Utc>,
    ) -> AppResult<bool> {
        let _ = deprecated_until;
        KeyQueries::compare_and_set_active_to_deprecated(&self.pool, *key_id)
            .await
            .map_err(AppError::from)
    }

    async fn rotate_active_key(
        &self,
        service_id: &ServiceId,
        algorithm: KeyAlgorithm,
        new_key: &crate::domain::keys::models::KeyPairEntity,
        deprecated_until: Option<DateTime<Utc>>,
    ) -> AppResult<bool> {
        let old_status = if deprecated_until.is_some() {
            "Deprecated"
        } else {
            "Compromised"
        };

        KeyQueries::rotate_active_key(
            &self.pool,
            &service_id.0,
            &format!("{:?}", algorithm),
            old_status,
            new_key.id,
            new_key.version,
            &new_key.encrypted_private_key.ciphertext,
            &new_key.public_key_pem,
            &format!("{:?}", new_key.purpose),
        )
        .await
        .map_err(AppError::from)
    }

    async fn get_deprecated_keys_expired(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<Vec<KeyPairEntity>> {
        let rows = KeyQueries::get_deprecated_keys_expired(&self.pool)
            .await
            .map_err(AppError::from)?;

        let mut out = Vec::new();
        for row in rows {
            let entity = map_key_row(row)?;
            if matches!(entity.status, KeyStatus::Deprecated { valid_until } if valid_until <= now)
            {
                out.push(entity);
            }
        }
        Ok(out)
    }

    async fn get_active_or_valid_deprecated_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        now: DateTime<Utc>,
    ) -> AppResult<Option<KeyPairEntity>> {
        let rows = KeyQueries::get_active_or_valid_deprecated_key(&self.pool)
            .await
            .map_err(AppError::from)?;

        for row in rows {
            let entity = map_key_row(row)?;
            if entity.service_id == *service_id
                && entity.algorithm == algo
                && (matches!(entity.status, KeyStatus::Active)
                    || matches!(entity.status, KeyStatus::Deprecated { valid_until } if valid_until > now))
            {
                return Ok(Some(entity));
            }
        }

        Ok(None)
    }

    async fn get_all_keys(&self) -> AppResult<Vec<KeyPairEntity>> {
        let rows = KeyQueries::get_all_keys(&self.pool)
            .await
            .map_err(AppError::from)?;

        rows.into_iter().map(map_key_row).collect()
    }

    async fn update_encrypted_key(
        &self,
        key_id: &Uuid,
        encrypted: EncryptedPrivateKey,
    ) -> AppResult<()> {
        KeyQueries::update_encrypted_key(&self.pool, *key_id, &encrypted.ciphertext)
            .await
            .map_err(AppError::from)?;

        Ok(())
    }

    async fn get_keys_needing_rewrap(
        &self,
        current_master_version: i32,
        batch_size: usize,
    ) -> AppResult<Vec<KeyPairEntity>> {
        let _ = current_master_version;
        let rows = KeyQueries::get_keys_needing_rewrap(&self.pool)
            .await
            .map_err(AppError::from)?;

        let mut out = Vec::new();
        for row in rows.into_iter().take(batch_size) {
            out.push(map_key_row(row)?);
        }
        Ok(out)
    }

    async fn update_encrypted_keys_batch(
        &self,
        updates: Vec<(Uuid, EncryptedPrivateKey, i32)>,
    ) -> AppResult<usize> {
        let batch: Vec<(Uuid, Vec<u8>)> = updates
            .into_iter()
            .map(|(key_id, encrypted, _)| (key_id, encrypted.ciphertext))
            .collect();

        KeyQueries::update_encrypted_keys_batch(&self.pool, batch)
            .await
            .map_err(AppError::from)
    }
}

fn map_key_row(row: KeyDbRow) -> AppResult<KeyPairEntity> {
    let algorithm = match row.algorithm.as_str() {
        "Ed25519" => KeyAlgorithm::Ed25519,
        "X25519" => KeyAlgorithm::X25519,
        "AES256GCM" => KeyAlgorithm::AES256GCM,
        "HmacSha256" => KeyAlgorithm::HmacSha256,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown algorithm in database: {}",
                row.algorithm
            )));
        }
    };

    let purpose = match row.purpose.as_str() {
        "Signing" => KeyPurpose::Signing,
        "Encryption" => KeyPurpose::Encryption,
        "Authentication" => KeyPurpose::Authentication,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown purpose in database: {}",
                row.purpose
            )));
        }
    };

    let status = match row.status.as_str() {
        "Active" => KeyStatus::Active,
        "Revoked" => KeyStatus::Revoked,
        "Compromised" => KeyStatus::Compromised,
        "Deprecated" => KeyStatus::Deprecated {
            valid_until: row.created_at + chrono::Duration::minutes(30),
        },
        "Expired" => KeyStatus::Expired,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown key status in database: {}",
                row.status
            )));
        }
    };

    Ok(KeyPairEntity {
        id: row.id,
        service_id: ServiceId(row.service_id),
        algorithm,
        purpose,
        public_key_pem: row.public_key_pem,
        encrypted_private_key: EncryptedPrivateKey {
            ciphertext: row.encrypted_key_data,
            master_key_version: 0,
        },
        version: row.version as u32,
        status,
        created_at: row.created_at,
        expires_at: None,
    })
}
