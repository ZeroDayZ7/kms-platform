use crate::config::acl::ControlAction;
use crate::domain::crypto::KmsCryptoService;
use crate::domain::keys::models::ServiceId;
use crate::errors::{AppError, AppResult};
use crate::server::state::AppState;
use chrono::Utc;
use serde::Deserialize;
use sqlx::Postgres;
use sqlx::Transaction;
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct ImportBootstrapInput {
    pub version: u32,
    pub credentials: Vec<serde_json::Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BootstrapCredentialRecord {
    service_id: String,
    target_type: String,
    target_db: String,
    resource: Option<String>,
    username: String,
    password: String,
    ttl_seconds: Option<u64>,
}

pub async fn import_bootstrap(
    state: AppState,
    caller_service: String,
    input: ImportBootstrapInput,
) -> AppResult<usize> {
    // Authorization: ensure caller has BootstrapImport action
    let compiled = state.settings.acl.compile();
    if !compiled.has_control_action(
        &ServiceId(caller_service.clone()),
        &ControlAction::BootstrapImport,
    ) {
        error!(caller_service = %caller_service, "Forbidden attempt to perform BootstrapImport");
        return Err(AppError::Forbidden);
    }

    if input.version != 1 {
        return Err(AppError::ValidationError(
            "Unsupported bootstrap version".into(),
        ));
    }

    // Parse records z zalogowaniem każdego wpisu
    let mut records: Vec<BootstrapCredentialRecord> = Vec::new();
    for (idx, v) in input.credentials.into_iter().enumerate() {
        match serde_json::from_value::<BootstrapCredentialRecord>(v.clone()) {
            Ok(rec) => {
                info!(
                    index = idx,
                    service_id = %rec.service_id,
                    target_type = %rec.target_type,
                    target_db = %rec.target_db,
                    username = %rec.username,
                    "Parsed bootstrap record successfully"
                );
                records.push(rec);
            }
            Err(err) => {
                error!(
                    index = idx,
                    raw_json = %v,
                    error = %err,
                    "Failed to deserialize bootstrap credential record"
                );
                return Err(AppError::ValidationError(format!(
                    "Invalid credential record schema at index {}: {}",
                    idx, err
                )));
            }
        }
    }

    if records.is_empty() {
        return Err(AppError::ValidationError("No credentials to import".into()));
    }

    // Atomic import: one DB transaction for all
    let mut tx: Transaction<'_, Postgres> = state.db.begin().await?;

    let mut inserted = 0usize;
    let now = Utc::now();

    for rec in records.iter() {
        info!(
            service_id = %rec.service_id,
            target_type = %rec.target_type,
            target_db = %rec.target_db,
            username = %rec.username,
            "Inserting credential record into PostgreSQL"
        );

        // POPRAWKA: Dodano target_type do zapytania o duplikaty (zgodnie z indeksem bazy)
        let exists: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM db_credentials 
            WHERE service_id = $1 AND target_type = $2 AND target_db = $3 AND username = $4 AND status = 'ACTIVE' 
            LIMIT 1
            "#,
        )
        .bind(&rec.service_id)
        .bind(&rec.target_type)
        .bind(&rec.target_db)
        .bind(&rec.username)
        .fetch_optional(&mut *tx)
        .await?;

        if exists.is_some() {
            let _ = tx.rollback().await;
            error!(
                service_id = %rec.service_id,
                target_type = %rec.target_type,
                target_db = %rec.target_db,
                username = %rec.username,
                "Duplicate active credential error"
            );
            return Err(AppError::ValidationError(format!(
                "Duplicate active credential: {}@{} ({})",
                rec.username, rec.target_db, rec.target_type
            )));
        }

        // Fetch latest KEK id for service
        let kek_row: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM keys WHERE service_id = $1 AND is_active = true ORDER BY version DESC LIMIT 1",
        )
        .bind(&rec.service_id)
        .fetch_optional(&mut *tx)
        .await?;

        if kek_row.is_none() {
            let _ = tx.rollback().await;
            error!(service_id = %rec.service_id, "No active KEK found for service");
            return Err(AppError::Internal(format!(
                "No active KEK for service: {}",
                rec.service_id
            )));
        }
        let kek_id = kek_row.unwrap(); // Używamy unwrap po sprawdzeniu is_none()

        // Encrypt password via crypto service (vHSM)
        let pwd_bytes = rec.password.as_bytes().to_vec();
        let pwd_zero = Zeroizing::new(pwd_bytes);
        let encrypted = state
            .crypto_service
            .encrypt_private_key(pwd_zero.as_ref())
            .await
            .map_err(|e| AppError::CryptoError(format!("Failed to encrypt credential: {}", e)))?;

        if encrypted.ciphertext.len() < 12 {
            let _ = tx.rollback().await;
            return Err(AppError::CryptoError("Encrypted payload too short".into()));
        }
        let nonce = encrypted.ciphertext[..12].to_vec();

        // POPRAWKA: Precyzyjne wskazanie kolumn oraz jawnego statusu 'ACTIVE'
        sqlx::query(
            r#"
            INSERT INTO db_credentials 
                (id, service_id, target_type, target_db, resource, username, encrypted_password, nonce, kek_id, status, created_at)
            VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE', $10)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&rec.service_id)
        .bind(&rec.target_type)
        .bind(&rec.target_db)
        .bind(rec.resource.as_deref().unwrap_or(""))
        .bind(&rec.username)
        .bind(&encrypted.ciphertext)
        .bind(&nonce)
        .bind(kek_id) // Użycie wymaganego UUID (nie Option<Uuid>)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        inserted += 1;
    }

    // Insert audit log for import
    let action = "bootstrap:import";
    let prev_hash_row: Option<String> =
        sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let hash = kms_core::audit::compute_audit_hash(&kms_core::audit::AuditHashInput {
        id: &Uuid::new_v4().to_string(),
        caller_service: &caller_service,
        target_service: "bootstrap",
        action,
        algorithm: "bootstrap-import",
        status: "Success",
        reason: Some(&format!("imported {} credentials", inserted)),
        prev_hash,
        timestamp: &now,
    });

    sqlx::query(
        r#"
        INSERT INTO audit_logs (id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(caller_service)
    .bind("bootstrap")
    .bind(action)
    .bind("bootstrap-import")
    .bind("Success")
    .bind(format!("imported {} credentials", inserted))
    .bind(prev_hash)
    .bind(hash)
    .bind(Vec::<u8>::new())
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    info!(
        count = inserted,
        "Successfully committed bootstrap import transaction"
    );

    Ok(inserted)
}
