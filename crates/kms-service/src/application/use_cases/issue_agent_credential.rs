use chrono::{DateTime, Utc};
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    errors::{AppError, AppResult},
    server::state::AppState,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

pub const DEFAULT_PASSWORD_LEN: usize = 32;

pub struct GeneratedCredentialBlob {
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub plaintext_password: zeroize::Zeroizing<String>,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct IssueAgentCredentialInput {
    pub caller_service: String,
    pub target_service: String,
    pub target_type: String,
    pub resource: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct IssueAgentCredentialOutput {
    pub credential_id: Uuid,
    pub username: String,
    pub password: String,
    pub expires_at: DateTime<Utc>,
}

pub struct IssueAgentCredentialUseCase;

impl IssueAgentCredentialUseCase {
    pub async fn execute(
        state: &AppState,
        input: IssueAgentCredentialInput,
    ) -> AppResult<IssueAgentCredentialOutput> {
        let target_type_clean = input.target_type.to_lowercase();
        let action = format!("kms:credentials:provision:{target_type_clean}");
        let resource_arn = format!("arn:kms:{target_type_clean}:{}", input.resource);

        // 1. Walidacja IAM Policy
        if !state
            .iam_policy
            .is_action_allowed(&input.caller_service, &action, &resource_arn)
        {
            tracing::warn!(
                caller = %input.caller_service,
                action = %action,
                resource = %resource_arn,
                "IAM Policy access denied for agent request"
            );
            return Err(AppError::Forbidden);
        }

        // 2. Generowanie poświadczeń
        let kek_id = fetch_latest_kek_id(&state.db, &input.caller_service).await?;
        let username = build_generic_username(&input.caller_service, &input.target_service);
        let generated = generate_secure_credential(
            &state.crypto_service,
            kek_id,
            &username,
            DEFAULT_PASSWORD_LEN,
        )
        .await?;

        // Lookup target resource admin connection (encrypted) and decrypt it via vHSM
        let target_row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, connection_url_encrypted FROM target_resources WHERE target_name = $1 AND active = true LIMIT 1",
        )
        .bind(&input.target_service)
        .fetch_optional(&state.db)
        .await?;

        let (target_id, conn_encrypted) = match target_row {
            Some(v) => v,
            None => {
                return Err(AppError::NotFound(format!(
                    "Target resource not found: {}",
                    input.target_service
                )));
            }
        };

        let admin_conn_bytes = state
            .crypto_service
            .decrypt_bytes(&conn_encrypted)
            .await
            .map_err(|e| {
                AppError::CryptoError(format!("Failed to decrypt target connection string: {e}"))
            })?;
        let admin_conn = String::from_utf8(admin_conn_bytes).map_err(|_| {
            AppError::CryptoError(
                "Decrypted target connection string is not valid UTF-8".to_string(),
            )
        })?;

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(input.ttl_seconds as i64);

        // 3. Utworzenie konta w zewnętrznej usłudze (zgodnie z interfejsem TargetResourceProvider)
        // 3. ATOMOWY ZAPIS W BAZIE KMS (Transakcja SQL)
        // Insert preliminary record inside a transaction; we will commit only after provider succeeds.
        let mut tx: Transaction<'_, Postgres> = state.db.begin().await?;

        insert_db_credential_tx(
            &mut tx,
            generated.credential_id,
            &input.caller_service,
            &input.target_service,
            &generated,
            kek_id,
            created_at,
        )
        .await?;

        // 4. Create account in target provider using plaintext password from vHSM.
        let provider = state.provider_factory.get(&target_type_clean)?;

        // Decode base64 plaintext password into secure Zeroizing buffer for provider call
        let secret_bytes = BASE64
            .decode(generated.plaintext_password.as_str())
            .map_err(|e| {
                AppError::ValidationError(format!("Invalid base64 password from vHSM: {e}"))
            })?;
        let secret_zero = zeroize::Zeroizing::new(secret_bytes);

        let provider_result = provider
            .create_user(
                &admin_conn,
                &username,
                input.ttl_seconds as i64,
                Some(secret_zero.as_ref()),
            )
            .await;

        // Ensure secret bytes are zeroed as soon as possible
        drop(secret_zero);

        let provider_credential = match provider_result {
            Ok(c) => c,
            Err(e) => {
                // Provider failed: rollback DB transaction so no pending record remains
                let _ = tx.rollback().await;
                return Err(e);
            }
        };

        // Update DB record with actual provider username (if provider generated a different one)
        update_db_credential_username_tx(
            &mut tx,
            generated.credential_id,
            &provider_credential.username,
        )
        .await?;

        insert_audit_log_tx(
            &mut tx,
            &input.caller_service,
            &input.target_service,
            &action,
            &generated.credential_id,
            created_at,
        )
        .await?;

        // Insert provisioned_credentials record in same transaction
        insert_provisioned_credential_tx(
            &mut tx,
            Uuid::new_v4(),
            &input.caller_service,
            target_id,
            &provider_credential.username,
            &generated.encrypted_password,
            &username, // granted_role
            expires_at,
        )
        .await?;

        // Commit transaction now that provider account was created and DB updated
        if let Err(commit_err) = tx.commit().await {
            // Attempt best-effort cleanup: revoke provider account to avoid orphan
            let _ = provider
                .revoke_user(&input.target_service, &provider_credential.username)
                .await;

            return Err(AppError::Internal(format!(
                "DB commit failed: {commit_err}"
            )));
        }

        Ok(IssueAgentCredentialOutput {
            credential_id: generated.credential_id,
            username: generated.username,
            password: generated.plaintext_password.as_str().to_string(),
            expires_at,
        })
    }
}

// --- Funkcje pomocnicze ---

pub fn build_generic_username(caller_service: &str, target_service: &str) -> String {
    format!("kms_{}_{}", caller_service, target_service)
}

pub async fn fetch_latest_kek_id(
    db: &sqlx::PgPool,
    caller_service: &str,
) -> AppResult<Option<Uuid>> {
    let row: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM keys WHERE service_id = $1 AND is_active = true ORDER BY version DESC LIMIT 1"
    )
    .bind(caller_service)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn generate_secure_credential(
    crypto_service: &crate::infrastructure::crypto::kms_service::VhsmCryptoService,
    kek_id: Option<Uuid>,
    username: &str,
    length: usize,
) -> AppResult<GeneratedCredentialBlob> {
    // Ensure KEK exists (KMS responsibility remains to have an active KEK record for metadata)
    let _key_id =
        kek_id.ok_or_else(|| AppError::Internal("No active KEK found for encryption".into()))?;

    // Delegate credential generation to vHSM
    let (credential_id, password_b64, wrapped_password, _key_version) = crypto_service
        .generate_credential(length)
        .await
        .map_err(|e| {
            AppError::CryptoError(format!("Failed to generate credential via vHSM: {e}"))
        })?;

    // Extract nonce (first 12 bytes) if present
    if wrapped_password.len() < 12 {
        return Err(AppError::CryptoError(
            "Wrapped password payload too short (missing nonce)".to_string(),
        ));
    }
    let nonce = wrapped_password[..12].to_vec();

    // Parse vHSM credential_id (hex 16 bytes) into Uuid for DB
    let id_bytes = hex::decode(&credential_id)
        .map_err(|_| AppError::CryptoError("Invalid credential id format from vHSM".to_string()))?;
    if id_bytes.len() != 16 {
        return Err(AppError::CryptoError(
            "Credential id from vHSM has invalid length".to_string(),
        ));
    }
    let uuid = Uuid::from_slice(&id_bytes).map_err(|_| {
        AppError::CryptoError("Failed to parse credential id into UUID".to_string())
    })?;

    Ok(GeneratedCredentialBlob {
        credential_id: uuid,
        username: username.to_string(),
        plaintext_password: zeroize::Zeroizing::new(password_b64),
        encrypted_password: wrapped_password,
        nonce,
    })
}

// --- Funkcje pomocnicze transakcyjne ---

pub async fn insert_db_credential_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    service_id: &str,
    target_db: &str,
    blob: &GeneratedCredentialBlob,
    kek_id: Option<Uuid>,
    created_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO db_credentials 
            (id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at)
        VALUES 
            ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(id)
    .bind(service_id)
    .bind(target_db)
    .bind(&blob.username)
    .bind(&blob.encrypted_password)
    .bind(&blob.nonce)
    .bind(kek_id)
    .bind(created_at)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

pub async fn update_db_credential_username_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    username: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE db_credentials
        SET username = $1
        WHERE id = $2
        "#,
    )
    .bind(username)
    .bind(id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_provisioned_credential_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    service_id: &str,
    target_id: Uuid,
    username: &str,
    password_encrypted: &[u8],
    granted_role: &str,
    expires_at: DateTime<Utc>,
) -> AppResult<()> {
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
    .await?;

    Ok(())
}

pub async fn insert_audit_log_tx(
    tx: &mut Transaction<'_, Postgres>,
    caller_service: &str,
    target_service: &str,
    action: &str,
    credential_id: &Uuid,
    timestamp: DateTime<Utc>,
) -> AppResult<()> {
    let prev_hash_row: Option<String> =
        sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await?;

    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let hash = compute_audit_hash(&AuditHashInput {
        id: &credential_id.to_string(),
        caller_service,
        target_service,
        action,
        algorithm: "db-credentials",
        status: "Success",
        reason: Some("agent credential provisioned"),
        prev_hash,
        timestamp: &timestamp,
    });

    sqlx::query(
        r#"
        INSERT INTO audit_logs 
            (id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at) 
        VALUES 
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(caller_service)
    .bind(target_service)
    .bind(action)
    .bind("db-credentials")
    .bind("Success")
    .bind("agent credential provisioned")
    .bind(prev_hash)
    .bind(hash)
    .bind(Vec::<u8>::new())
    .bind(timestamp)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
