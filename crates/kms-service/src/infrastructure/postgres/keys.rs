use chrono::{DateTime, Utc};
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
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl KeyRepository for PgKeyRepository {
    async fn save_key(&self, key_pair: &KeyPairEntity) -> AppResult<()> {
        let status = format!("{:?}", key_pair.status)
            .replace("Deprecated { valid_until: ... }", "Deprecated");
        let is_active = matches!(key_pair.status, KeyStatus::Active);

        crate::infrastructure::sqlc::queries::save_key(
            &self.pool,
            crate::infrastructure::sqlc::queries::SaveKeyParams {
                id: key_pair.id,
                service_id: key_pair.service_id.0.clone(),
                algorithm: format!("{:?}", key_pair.algorithm),
                version: key_pair.version as i32,
                encrypted_key_data: key_pair.encrypted_private_key.ciphertext.clone(),
                public_key_pem: key_pair.public_key_pem.clone(),
                purpose: format!("{:?}", key_pair.purpose),
                status: status.clone(),
                is_active,
            },
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
        match crate::infrastructure::sqlc::queries::get_active_key(
            &self.pool,
            crate::infrastructure::sqlc::queries::GetActiveKeyParams {
                service_id: service_id.0.clone(),
                algorithm: format!("{:?}", algo),
            },
        )
        .await
        {
            Ok(row) => Ok(Some(map_active_key_row(row)?)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(err) => Err(AppError::from(err)),
        }
    }

    async fn get_key_by_version(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
        version: u32,
    ) -> AppResult<Option<KeyPairEntity>> {
        match crate::infrastructure::sqlc::queries::get_key_by_version(
            &self.pool,
            crate::infrastructure::sqlc::queries::GetKeyByVersionParams {
                service_id: service_id.0.clone(),
                algorithm: format!("{:?}", algo),
                version: version as i32,
            },
        )
        .await
        {
            Ok(row) => Ok(Some(map_key_by_version_row(row)?)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(err) => Err(AppError::from(err)),
        }
    }

    async fn get_all_active_public_keys(&self) -> AppResult<Vec<KeyPairEntity>> {
        let rows = crate::infrastructure::sqlc::queries::get_all_active_keys(&self.pool)
            .await
            .map_err(AppError::from)?;
        rows.into_iter().map(map_all_active_key_row).collect()
    }

    async fn deactivate_keys_for_service(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> AppResult<()> {
        sqlx::query("UPDATE keys SET status = 'Revoked', is_active = false WHERE service_id = $1 AND algorithm = $2 AND is_active = true")
            .bind(service_id.0.clone())
            .bind(format!("{:?}", algo))
            .execute(&self.pool)
            .await?;
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

        crate::infrastructure::sqlc::queries::update_key_status(
            &self.pool,
            crate::infrastructure::sqlc::queries::UpdateKeyStatusParams {
                id: *key_id,
                status: status_str.to_string(),
                is_active,
            },
        )
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
        let result = sqlx::query("UPDATE keys SET status = 'Deprecated', is_active = false WHERE id = $1 AND status = 'Active'")
            .bind(*key_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_deprecated_keys_expired(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<Vec<KeyPairEntity>> {
        let rows = sqlx::query_as::<_, crate::infrastructure::sqlc::queries::GetAllKeysRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE status = 'Deprecated' ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for row in rows {
            let entity = map_all_key_row(row)?;
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
        let rows = crate::infrastructure::sqlc::queries::get_all_active_keys(&self.pool)
            .await
            .map_err(AppError::from)?;
        for row in rows {
            let entity = map_all_active_key_row(row)?;
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
        let rows = crate::infrastructure::sqlc::queries::get_all_keys(&self.pool)
            .await
            .map_err(AppError::from)?;
        rows.into_iter().map(map_all_key_row).collect()
    }

    async fn update_encrypted_key(
        &self,
        key_id: &Uuid,
        encrypted: EncryptedPrivateKey,
    ) -> AppResult<()> {
        crate::infrastructure::sqlc::queries::update_encrypted_key(
            &self.pool,
            crate::infrastructure::sqlc::queries::UpdateEncryptedKeyParams {
                id: *key_id,
                encrypted_key_data: encrypted.ciphertext,
            },
        )
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
        let rows = crate::infrastructure::sqlc::queries::get_all_keys(&self.pool)
            .await
            .map_err(AppError::from)?;
        let mut out = Vec::new();
        for row in rows.into_iter().take(batch_size) {
            out.push(map_all_key_row(row)?);
        }
        Ok(out)
    }

    async fn update_encrypted_keys_batch(
        &self,
        updates: Vec<(Uuid, EncryptedPrivateKey, i32)>,
    ) -> AppResult<usize> {
        let mut updated = 0usize;
        for (key_id, encrypted, _current_version) in updates {
            if self.update_encrypted_key(&key_id, encrypted).await.is_ok() {
                updated += 1;
            }
        }
        Ok(updated)
    }
}

fn map_active_key_row(
    row: crate::infrastructure::sqlc::queries::GetActiveKeyRow,
) -> AppResult<KeyPairEntity> {
    map_key_row(
        row.id,
        row.service_id,
        row.algorithm,
        row.version as u32,
        row.encrypted_key_data,
        row.public_key_pem,
        row.purpose,
        row.status,
        row.created_at,
    )
}

fn map_key_by_version_row(
    row: crate::infrastructure::sqlc::queries::GetKeyByVersionRow,
) -> AppResult<KeyPairEntity> {
    map_key_row(
        row.id,
        row.service_id,
        row.algorithm,
        row.version as u32,
        row.encrypted_key_data,
        row.public_key_pem,
        row.purpose,
        row.status,
        row.created_at,
    )
}

fn map_all_active_key_row(
    row: crate::infrastructure::sqlc::queries::GetAllActiveKeysRow,
) -> AppResult<KeyPairEntity> {
    map_key_row(
        row.id,
        row.service_id,
        row.algorithm,
        row.version as u32,
        row.encrypted_key_data,
        row.public_key_pem,
        row.purpose,
        row.status,
        row.created_at,
    )
}

fn map_all_key_row(
    row: crate::infrastructure::sqlc::queries::GetAllKeysRow,
) -> AppResult<KeyPairEntity> {
    map_key_row(
        row.id,
        row.service_id,
        row.algorithm,
        row.version as u32,
        row.encrypted_key_data,
        row.public_key_pem,
        row.purpose,
        row.status,
        row.created_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn map_key_row(
    id: Uuid,
    service_id: String,
    algorithm: String,
    version: u32,
    encrypted_key_data: Vec<u8>,
    public_key_pem: String,
    purpose: String,
    status: String,
    created_at: DateTime<Utc>,
) -> AppResult<KeyPairEntity> {
    let algorithm = match algorithm.as_str() {
        "Ed25519" => KeyAlgorithm::Ed25519,
        "X25519" => KeyAlgorithm::X25519,
        "AES256GCM" => KeyAlgorithm::AES256GCM,
        "HmacSha256" => KeyAlgorithm::HmacSha256,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown algorithm in database: {}",
                algorithm
            )));
        }
    };

    let purpose = match purpose.as_str() {
        "Signing" => KeyPurpose::Signing,
        "Encryption" => KeyPurpose::Encryption,
        "Authentication" => KeyPurpose::Authentication,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown purpose in database: {}",
                purpose
            )));
        }
    };

    let status = match status.as_str() {
        "Active" => KeyStatus::Active,
        "Revoked" => KeyStatus::Revoked,
        "Compromised" => KeyStatus::Compromised,
        "Deprecated" => KeyStatus::Deprecated {
            valid_until: created_at + chrono::Duration::minutes(30),
        },
        "Expired" => KeyStatus::Expired,
        _ => {
            return Err(AppError::Internal(format!(
                "Unknown key status in database: {}",
                status
            )));
        }
    };

    Ok(KeyPairEntity {
        id,
        service_id: ServiceId(service_id),
        algorithm,
        purpose,
        public_key_pem,
        encrypted_private_key: EncryptedPrivateKey {
            ciphertext: encrypted_key_data,
            master_key_version: 0,
        },
        version,
        status,
        created_at,
        expires_at: None,
    })
}
