use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
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

#[derive(Debug, Clone, FromRow)]
struct KeyRow {
    pub id: Uuid,
    pub service_id: String,
    pub algorithm: String,
    pub version: i32,
    pub encrypted_key_data: Vec<u8>,
    pub public_key_pem: String,
    pub purpose: String,
    pub status: String,
    #[allow(dead_code)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl KeyRepository for PgKeyRepository {
    async fn save_key(&self, key_pair: &KeyPairEntity) -> AppResult<()> {
        let status = format!("{:?}", key_pair.status)
            .replace("Deprecated { valid_until: ... }", "Deprecated");
        let is_active = matches!(key_pair.status, KeyStatus::Active);

        sqlx::query(
            r#"
            INSERT INTO keys (
                id, service_id, algorithm, version, encrypted_key_data,
                public_key_pem, purpose, status, is_active, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()
            )
            ON CONFLICT (service_id, algorithm, version)
            DO UPDATE SET
                encrypted_key_data = EXCLUDED.encrypted_key_data,
                public_key_pem = EXCLUDED.public_key_pem,
                purpose = EXCLUDED.purpose,
                status = EXCLUDED.status,
                is_active = EXCLUDED.is_active,
                created_at = NOW()
            "#,
        )
        .bind(key_pair.id)
        .bind(key_pair.service_id.0.clone())
        .bind(format!("{:?}", key_pair.algorithm))
        .bind(key_pair.version as i32)
        .bind(key_pair.encrypted_private_key.ciphertext.clone())
        .bind(key_pair.public_key_pem.clone())
        .bind(format!("{:?}", key_pair.purpose))
        .bind(status)
        .bind(is_active)
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(())
    }

    async fn get_active_key(
        &self,
        service_id: &ServiceId,
        algo: KeyAlgorithm,
    ) -> AppResult<Option<KeyPairEntity>> {
        let row = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE service_id = $1 AND algorithm = $2 AND is_active = true LIMIT 1"
        )
        .bind(service_id.0.clone())
        .bind(format!("{:?}", algo))
        .fetch_optional(&self.pool)
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
        let row = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE service_id = $1 AND algorithm = $2 AND version = $3 LIMIT 1"
        )
        .bind(service_id.0.clone())
        .bind(format!("{:?}", algo))
        .bind(version as i32)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)?;

        match row {
            Some(r) => Ok(Some(map_key_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_all_active_public_keys(&self) -> AppResult<Vec<KeyPairEntity>> {
        let rows = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE is_active = true ORDER BY service_id, algorithm, version DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::from)?;

        rows.into_iter().map(map_key_row).collect()
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

        sqlx::query("UPDATE keys SET status = $2, is_active = $3 WHERE id = $1")
            .bind(*key_id)
            .bind(status_str)
            .bind(is_active)
            .execute(&self.pool)
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

        let rows = sqlx::query(
            r#"
            WITH retired AS (
                UPDATE keys
                SET status = $3,
                    is_active = FALSE,
                    created_at = NOW()
                WHERE service_id = $1
                  AND algorithm = $2
                  AND is_active = TRUE
                RETURNING id
            )
            INSERT INTO keys (
                id, service_id, algorithm, version, encrypted_key_data,
                public_key_pem, purpose, status, is_active, created_at
            )
            VALUES (
                $4, $1, $2, $5, $6, $7, $8, 'Active', TRUE, NOW()
            )
            ON CONFLICT (service_id, algorithm, version)
            DO UPDATE SET
                encrypted_key_data = EXCLUDED.encrypted_key_data,
                public_key_pem = EXCLUDED.public_key_pem,
                purpose = EXCLUDED.purpose,
                status = EXCLUDED.status,
                is_active = EXCLUDED.is_active,
                created_at = NOW();
            "#,
        )
        .bind(service_id.0.clone())
        .bind(format!("{:?}", algorithm))
        .bind(old_status)
        .bind(new_key.id)
        .bind(new_key.version as i32)
        .bind(new_key.encrypted_private_key.ciphertext.clone())
        .bind(new_key.public_key_pem.clone())
        .bind(format!("{:?}", new_key.purpose))
        .execute(&self.pool)
        .await?;

        Ok(rows.rows_affected() == 1)
    }

    async fn get_deprecated_keys_expired(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<Vec<KeyPairEntity>> {
        let rows = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE status = 'Deprecated' ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

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
        let rows = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE is_active = true ORDER BY service_id, algorithm, version DESC"
        )
        .fetch_all(&self.pool)
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
        let rows = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::from)?;

        rows.into_iter().map(map_key_row).collect()
    }

    async fn update_encrypted_key(
        &self,
        key_id: &Uuid,
        encrypted: EncryptedPrivateKey,
    ) -> AppResult<()> {
        sqlx::query("UPDATE keys SET encrypted_key_data = $2 WHERE id = $1")
            .bind(*key_id)
            .bind(encrypted.ciphertext)
            .execute(&self.pool)
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
        let rows = sqlx::query_as::<_, KeyRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
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
        let mut tx = self.pool.begin().await?;
        let mut updated = 0usize;

        for (key_id, encrypted, _current_version) in updates {
            let res = sqlx::query("UPDATE keys SET encrypted_key_data = $2 WHERE id = $1")
                .bind(key_id)
                .bind(encrypted.ciphertext)
                .execute(&mut *tx)
                .await;

            if let Err(e) = res {
                tx.rollback().await?;
                return Err(AppError::from(e));
            }

            updated += 1;
        }

        tx.commit().await?;
        Ok(updated)
    }
}

fn map_key_row(row: KeyRow) -> AppResult<KeyPairEntity> {
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
