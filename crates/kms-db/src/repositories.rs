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
    ) -> Result<Option<(Uuid, Vec<u8>)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, Vec<u8>)>(
            "SELECT id, connection_url_encrypted FROM target_resources WHERE target_name = $1 AND active = true LIMIT 1",
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
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id FROM keys
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
        username: &str,
        password_encrypted: &[u8],
        granted_role: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO provisioned_credentials
                (id, service_id, target_id, username, password_encrypted, granted_role, expires_at, revoked, created_at)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, false, $8)
            "#,
        )
        .bind(id)
        .bind(service_id)
        .bind(target_id)
        .bind(username)
        .bind(password_encrypted)
        .bind(granted_role)
        .bind(expires_at)
        .bind(Utc::now())
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

pub struct BootstrapQueries;

impl BootstrapQueries {
    pub async fn insert_target_resource(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        target_name: &str,
        target_type: &str,
        connection_url_encrypted: &[u8],
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO target_resources (id, target_name, target_type, connection_url_encrypted, active, created_at)
            VALUES ($1, $2, $3, $4, true, $5)
            ON CONFLICT (target_name)
            DO UPDATE SET
                target_type = EXCLUDED.target_type,
                connection_url_encrypted = EXCLUDED.connection_url_encrypted,
                active = true
            "#,
        )
        .bind(id)
        .bind(target_name)
        .bind(target_type)
        .bind(connection_url_encrypted)
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
        username: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id FROM db_credentials
            WHERE service_id = $1 AND target_type = $2 AND target_db = $3 AND username = $4 AND status = 'ACTIVE'
            LIMIT 1
            "#,
        )
        .bind(service_id)
        .bind(target_type)
        .bind(target_db)
        .bind(username)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn latest_kek_id(
        tx: &mut Transaction<'_, Postgres>,
        service_id: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM keys WHERE service_id = $1 AND is_active = true ORDER BY version DESC LIMIT 1",
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
        username: &str,
        encrypted_password: &[u8],
        nonce: &[u8],
        kek_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO db_credentials
                (id, service_id, target_type, target_db, resource, username, encrypted_password, nonce, kek_id, status, created_at)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE', $10)
            "#,
        )
        .bind(id)
        .bind(service_id)
        .bind(target_type)
        .bind(target_db)
        .bind(resource)
        .bind(username)
        .bind(encrypted_password)
        .bind(nonce)
        .bind(kek_id)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

pub struct DatabaseHealth;

impl DatabaseHealth {
    pub async fn ping(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").fetch_one(pool).await.map(|_| ())
    }
}
