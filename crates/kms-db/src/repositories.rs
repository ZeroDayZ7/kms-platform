use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub caller_service: String,
    pub target_service: String,
    pub action: String,
    pub algorithm: String,
    pub status: String,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<Vec<u8>>,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuditInsert {
    pub id: Uuid,
    pub caller_service: String,
    pub target_service: String,
    pub action: String,
    pub algorithm: String,
    pub status: String,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<Vec<u8>>,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct AuditQueries;

impl AuditQueries {
    pub async fn list_recent(
        pool: &PgPool,
        limit: Option<usize>,
        full: bool,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        if full {
            sqlx::query_as::<_, AuditRow>(
                r#"
                SELECT id, caller_service, target_service, action, algorithm, status, reason,
                       prev_hash, hash, signature, request_id, operation_id, target_id, metadata, created_at
                FROM audit_logs
                ORDER BY created_at ASC, id ASC
                "#,
            )
            .fetch_all(pool)
            .await
        } else {
            let mut rows = sqlx::query_as::<_, AuditRow>(
                r#"
                SELECT id, caller_service, target_service, action, algorithm, status, reason,
                       prev_hash, hash, signature, request_id, operation_id, target_id, metadata, created_at
                FROM audit_logs
                ORDER BY created_at DESC, id DESC
                LIMIT $1
                "#,
            )
            .bind((limit.unwrap_or(1000) + 1) as i64)
            .fetch_all(pool)
            .await?;
            rows.reverse();
            Ok(rows)
        }
    }

    pub async fn active_signing_public_keys(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar::<_, String>(
            "SELECT public_key_pem FROM keys WHERE purpose = 'Signing' AND is_active = TRUE",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn latest_hash(pool: &PgPool) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, String>(
            "SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn latest_hash_tx(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, String>(
            "SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn insert(pool: &PgPool, row: AuditInsert) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, caller_service, target_service, action, algorithm,
                status, reason, prev_hash, hash, signature, request_id,
                operation_id, target_id, metadata, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            "#,
        )
        .bind(row.id)
        .bind(row.caller_service)
        .bind(row.target_service)
        .bind(row.action)
        .bind(row.algorithm)
        .bind(row.status)
        .bind(row.reason)
        .bind(row.prev_hash)
        .bind(row.hash)
        .bind(row.signature)
        .bind(row.request_id)
        .bind(row.operation_id)
        .bind(row.target_id)
        .bind(row.metadata)
        .bind(row.created_at)
        .execute(pool)
        .await
        .map(|_| ())
    }

    pub async fn insert_tx(
        tx: &mut Transaction<'_, Postgres>,
        row: AuditInsert,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, caller_service, target_service, action, algorithm,
                status, reason, prev_hash, hash, signature, request_id,
                operation_id, target_id, metadata, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            "#,
        )
        .bind(row.id)
        .bind(row.caller_service)
        .bind(row.target_service)
        .bind(row.action)
        .bind(row.algorithm)
        .bind(row.status)
        .bind(row.reason)
        .bind(row.prev_hash)
        .bind(row.hash)
        .bind(row.signature)
        .bind(row.request_id)
        .bind(row.operation_id)
        .bind(row.target_id)
        .bind(row.metadata)
        .bind(row.created_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

pub struct CredentialQueries;

impl CredentialQueries {
    pub async fn fetch_target_resource(
        pool: &PgPool,
        target_name: &str,
    ) -> Result<Option<(Uuid, Vec<u8>, Option<String>)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, Vec<u8>, Option<String>)>(
            "SELECT id, connection_url_encrypted, default_role FROM target_resources WHERE target_name = $1 AND active = true LIMIT 1",
        )
        .bind(target_name)
        .fetch_optional(pool)
        .await
    }

    pub async fn revoke_active_credentials_for_target(
        tx: &mut Transaction<'_, Postgres>,
        service_id: &str,
        target_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE provisioned_credentials
            SET revoked = true
            WHERE service_id = $1
              AND target_id = $2
              AND revoked = false
            "#,
        )
        .bind(service_id)
        .bind(target_id)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    pub async fn fetch_latest_kek_id(
        pool: &PgPool,
        target_service_id: &str,
    ) -> Result<Option<(Uuid, i32)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, i32)>(
            r#"
            SELECT id, version FROM keys
            WHERE service_id = $1
              AND is_active = true
              AND algorithm = 'AES256GCM'
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(target_service_id)
        .fetch_optional(pool)
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_provisioned_credential(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        service_id: &str,
        target_id: Uuid,
        encrypted_credentials: &[u8],
        granted_role: &str,
        kek_id: Uuid,
        kek_version: i32,
        expires_at: DateTime<Utc>,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO provisioned_credentials
                (id, service_id, target_id, encrypted_credentials, granted_role, kek_id, kek_version, expires_at, revoked, status, created_at)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, false, $9, $10)
            "#,
        )
        .bind(id)
        .bind(service_id)
        .bind(target_id)
        .bind(encrypted_credentials)
        .bind(granted_role)
        .bind(kek_id)
        .bind(kek_version)
        .bind(expires_at)
        .bind(status)
        .bind(Utc::now())
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    pub async fn fetch_active_provisioned_credential(
        pool: &PgPool,
        service_id: &str,
        target_id: Uuid,
    ) -> Result<Option<(Uuid, Vec<u8>, DateTime<Utc>)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, Vec<u8>, DateTime<Utc>)>(
            r#"
            SELECT id, encrypted_credentials, expires_at
            FROM provisioned_credentials
            WHERE service_id = $1
              AND target_id = $2
              AND revoked = false
              AND status = 'ACTIVE'
              AND expires_at > NOW()
            LIMIT 1
            "#,
        )
        .bind(service_id)
        .bind(target_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn fetch_latest_active_provisioned_credential_for_service_target(
        pool: &PgPool,
        service_id: &str,
        target_id: Uuid,
    ) -> Result<Option<(Uuid, Vec<u8>, DateTime<Utc>)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, Vec<u8>, DateTime<Utc>)>(
            r#"
            SELECT id, encrypted_credentials, expires_at
            FROM provisioned_credentials
            WHERE service_id = $1
              AND target_id = $2
              AND revoked = false
              AND status = 'ACTIVE'
              AND expires_at > NOW()
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            "#,
        )
        .bind(service_id)
        .bind(target_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn update_provisioned_credential_status(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE provisioned_credentials
            SET status = $1
            WHERE id = $2
            "#,
        )
        .bind(status)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

pub struct BootstrapQueries;

impl BootstrapQueries {
    pub async fn target_resource_exists_by_id(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM target_resources WHERE id = $1)")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
    }

    pub async fn credential_exists_by_id(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM provisioned_credentials WHERE id = $1)",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await
    }

    pub async fn insert_target_resource(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        target_name: &str,
        target_type: &str,
        connection_url_encrypted: &[u8],
        default_role: Option<&str>,
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO target_resources (id, target_name, target_type, connection_url_encrypted, default_role, active, created_at)
            VALUES ($1, $2, $3, $4, $5, true, $6)
            ON CONFLICT (target_name)
            DO UPDATE SET
                target_type = EXCLUDED.target_type,
                connection_url_encrypted = EXCLUDED.connection_url_encrypted,
                default_role = EXCLUDED.default_role,
                active = true
            "#,
        )
        .bind(id)
        .bind(target_name)
        .bind(target_type)
        .bind(connection_url_encrypted)
        .bind(default_role)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    pub async fn active_credential_exists(
        tx: &mut Transaction<'_, Postgres>,
        service_id: &str,
        target_type: &str,
        target_db: &str,
        // username removed: uniqueness handled at application layer
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id FROM db_credentials
            WHERE service_id = $1 AND target_type = $2 AND target_db = $3 AND status = 'ACTIVE'
            LIMIT 1
            "#,
        )
        .bind(service_id)
        .bind(target_type)
        .bind(target_db)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn latest_kek_id(
        tx: &mut Transaction<'_, Postgres>,
        service_id: &str,
    ) -> Result<Option<(Uuid, i32)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, i32)>(
            "SELECT id, version FROM keys WHERE service_id = $1 AND is_active = true ORDER BY version DESC LIMIT 1",
        )
        .bind(service_id)
        .fetch_optional(&mut **tx)
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_db_credential(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        service_id: &str,
        target_type: &str,
        target_db: &str,
        resource: &str,
        encrypted_credentials: &[u8],
        kek_id: Uuid,
        kek_version: i32,
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO db_credentials
                (id, service_id, target_type, target_db, resource, encrypted_credentials, kek_id, kek_version, status, created_at)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE', $9)
            "#,
        )
        .bind(id)
        .bind(service_id)
        .bind(target_type)
        .bind(target_db)
        .bind(resource)
        .bind(encrypted_credentials)
        .bind(kek_id)
        .bind(kek_version)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct KeyDbRow {
    pub id: Uuid,
    pub service_id: String,
    pub algorithm: String,
    pub version: i32,
    pub encrypted_key_data: Vec<u8>,
    pub public_key_pem: String,
    pub purpose: String,
    pub status: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

pub struct KeyQueries;

impl KeyQueries {
    #[allow(clippy::too_many_arguments)]
    pub async fn save_key(
        pool: &PgPool,
        id: Uuid,
        service_id: &str,
        algorithm: &str,
        version: u32,
        encrypted_key_data: &[u8],
        public_key_pem: &str,
        purpose: &str,
        status: &str,
        is_active: bool,
    ) -> Result<(), sqlx::Error> {
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
        .bind(id)
        .bind(service_id)
        .bind(algorithm)
        .bind(version as i32)
        .bind(encrypted_key_data)
        .bind(public_key_pem)
        .bind(purpose)
        .bind(status)
        .bind(is_active)
        .execute(pool)
        .await
        .map(|_| ())
    }

    pub async fn get_active_key(
        pool: &PgPool,
        service_id: &str,
        algorithm: &str,
    ) -> Result<Option<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE service_id = $1 AND algorithm = $2 AND is_active = true LIMIT 1",
        )
        .bind(service_id)
        .bind(algorithm)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_key_by_version(
        pool: &PgPool,
        service_id: &str,
        algorithm: &str,
        version: u32,
    ) -> Result<Option<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE service_id = $1 AND algorithm = $2 AND version = $3 LIMIT 1",
        )
        .bind(service_id)
        .bind(algorithm)
        .bind(version as i32)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_all_active_public_keys(pool: &PgPool) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE is_active = true ORDER BY service_id, algorithm, version DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn get_all_active_keys(pool: &PgPool) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE is_active = true ORDER BY service_id, algorithm, version DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn deactivate_keys_for_service(
        pool: &PgPool,
        service_id: &str,
        algorithm: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE keys SET status = 'Revoked', is_active = false WHERE service_id = $1 AND algorithm = $2 AND is_active = true",
        )
        .bind(service_id)
        .bind(algorithm)
        .execute(pool)
        .await
        .map(|_| ())
    }

    pub async fn update_key_status(
        pool: &PgPool,
        key_id: Uuid,
        status: &str,
        is_active: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE keys SET status = $2, is_active = $3 WHERE id = $1")
            .bind(key_id)
            .bind(status)
            .bind(is_active)
            .execute(pool)
            .await
            .map(|_| ())
    }

    pub async fn compare_and_set_active_to_deprecated(
        pool: &PgPool,
        key_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE keys SET status = 'Deprecated', is_active = false WHERE id = $1 AND status = 'Active'",
        )
        .bind(key_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn rotate_active_key(
        pool: &PgPool,
        service_id: &str,
        algorithm: &str,
        old_status: &str,
        new_key_id: Uuid,
        new_key_version: u32,
        encrypted_key_data: &[u8],
        public_key_pem: &str,
        purpose: &str,
    ) -> Result<bool, sqlx::Error> {
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
        .bind(service_id)
        .bind(algorithm)
        .bind(old_status)
        .bind(new_key_id)
        .bind(new_key_version as i32)
        .bind(encrypted_key_data)
        .bind(public_key_pem)
        .bind(purpose)
        .execute(pool)
        .await?;

        Ok(rows.rows_affected() == 1)
    }

    pub async fn get_deprecated_keys_expired(pool: &PgPool) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE status = 'Deprecated' ORDER BY created_at DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn get_active_or_valid_deprecated_key(
        pool: &PgPool,
    ) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys WHERE is_active = true ORDER BY service_id, algorithm, version DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn get_all_keys(pool: &PgPool) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys ORDER BY created_at DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn update_encrypted_key(
        pool: &PgPool,
        key_id: Uuid,
        encrypted_key_data: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE keys SET encrypted_key_data = $2 WHERE id = $1")
            .bind(key_id)
            .bind(encrypted_key_data)
            .execute(pool)
            .await
            .map(|_| ())
    }

    pub async fn get_keys_needing_rewrap(pool: &PgPool) -> Result<Vec<KeyDbRow>, sqlx::Error> {
        sqlx::query_as::<_, KeyDbRow>(
            "SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at FROM keys ORDER BY created_at DESC",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn update_encrypted_keys_batch(
        pool: &PgPool,
        updates: Vec<(Uuid, Vec<u8>)>,
    ) -> Result<usize, sqlx::Error> {
        let mut tx = pool.begin().await?;
        let mut updated = 0usize;

        for (key_id, encrypted) in updates {
            let res = sqlx::query("UPDATE keys SET encrypted_key_data = $2 WHERE id = $1")
                .bind(key_id)
                .bind(encrypted)
                .execute(&mut *tx)
                .await;

            if let Err(err) = res {
                tx.rollback().await?;
                return Err(err);
            }
            updated += 1;
        }

        tx.commit().await?;
        Ok(updated)
    }
}

pub struct DatabaseHealth;

impl DatabaseHealth {
    pub async fn ping(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").fetch_one(pool).await.map(|_| ())
    }
}
