use crate::config::acl::ControlAction;
use crate::domain::crypto::KmsCryptoService;
use crate::domain::keys::models::ServiceId;
use crate::errors::{AppError, AppResult};
use crate::server::state::AppState;
use chrono::Utc;
use kms_db::repositories::{AuditQueries, BootstrapQueries};
use serde::Deserialize;
use sqlx::Postgres;
use sqlx::Transaction;
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct ImportBootstrapInput {
    pub version: u32,
    #[serde(default)]
    pub target_resources: Vec<serde_json::Value>,
    #[serde(default)]
    pub credentials: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TargetResourceRecord {
    pub target_name: String,
    pub target_type: String,
    pub connection_url: String,
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
    // 1. Weryfikacja uprawnień ACL
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

    info!(
        target_resources_len = input.target_resources.len(),
        credentials_len = input.credentials.len(),
        "Rozpoczynam przetwarzanie bootstrap import - stan wejściowy"
    );

    // 2. Walidacja sekcji Credentials
    let mut cred_records: Vec<BootstrapCredentialRecord> = Vec::new();
    for (idx, v) in input.credentials.into_iter().enumerate() {
        match serde_json::from_value::<BootstrapCredentialRecord>(v.clone()) {
            Ok(rec) => cred_records.push(rec),
            Err(err) => {
                error!(index = idx, raw_json = %v, error = %err, "Failed to deserialize bootstrap credential record");
                return Err(AppError::ValidationError(format!(
                    "Invalid credential record schema at index {}: {}",
                    idx, err
                )));
            }
        }
    }

    if input.target_resources.is_empty() && cred_records.is_empty() {
        return Err(AppError::ValidationError(
            "Nothing to import: both target_resources and credentials are empty".into(),
        ));
    }

    // 3. Rozpoczęcie ATOMOWEJ transakcji w bazie
    let mut tx: Transaction<'_, Postgres> = state.db.begin().await?;
    let mut inserted_total = 0usize;
    let now = Utc::now();

    // ==========================================
    // KROK A: IMPORT DO target_resources
    // ==========================================
    let mut target_records: Vec<TargetResourceRecord> = Vec::new();
    for (idx, v) in input.target_resources.into_iter().enumerate() {
        match serde_json::from_value::<TargetResourceRecord>(v.clone()) {
            Ok(rec) => target_records.push(rec),
            Err(err) => {
                error!(index = idx, raw_json = %v, error = %err, "Failed to deserialize target_resource record");
                return Err(AppError::ValidationError(format!(
                    "Invalid target_resource record schema at index {}: {}",
                    idx, err
                )));
            }
        }
    }

    info!(
        count = target_records.len(),
        "Rozpoczynam pętlę KROK A dla target_resources"
    );

    for target in target_records.iter() {
        info!(
            target_name = %target.target_name,
            target_type = %target.target_type,
            "Importing target resource master credentials"
        );

        // Szyfrowanie całego ciągu connection_url jako 1 pętla krypto
        let url_bytes = target.connection_url.as_bytes().to_vec();
        let url_zero = Zeroizing::new(url_bytes);
        let encrypted = state
            .crypto_service
            .encrypt_private_key(url_zero.as_ref())
            .await
            .map_err(|e| {
                AppError::CryptoError(format!("Failed to encrypt connection_url: {}", e))
            })?;

        BootstrapQueries::insert_target_resource(
            &mut tx,
            Uuid::new_v4(),
            &target.target_name,
            &target.target_type,
            &encrypted.ciphertext,
            now,
        )
        .await?;

        inserted_total += 1;
    }

    // ==========================================
    // KROK B: IMPORT DO db_credentials
    // ==========================================
    for rec in cred_records.iter() {
        info!(
            service_id = %rec.service_id,
            target_type = %rec.target_type,
            target_db = %rec.target_db,
            username = %rec.username,
            "Inserting static credential record into PostgreSQL"
        );

        let exists: Option<Uuid> = BootstrapQueries::active_credential_exists(
            &mut tx,
            &rec.service_id,
            &rec.target_type,
            &rec.target_db,
            &rec.username,
        )
        .await?;

        if exists.is_some() {
            let _ = tx.rollback().await;
            return Err(AppError::ValidationError(format!(
                "Duplicate active credential: {}@{} ({})",
                rec.username, rec.target_db, rec.target_type
            )));
        }

        let kek_row: Option<Uuid> =
            BootstrapQueries::latest_kek_id(&mut tx, &rec.service_id).await?;

        let kek_id = match kek_row {
            Some(id) => id,
            None => {
                let _ = tx.rollback().await;
                return Err(AppError::Internal(format!(
                    "No active KEK for service: {}",
                    rec.service_id
                )));
            }
        };

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

        BootstrapQueries::insert_db_credential(
            &mut tx,
            Uuid::new_v4(),
            &rec.service_id,
            &rec.target_type,
            &rec.target_db,
            rec.resource.as_deref().unwrap_or(""),
            &rec.username,
            &encrypted.ciphertext,
            &nonce,
            kek_id,
            now,
        )
        .await?;

        inserted_total += 1;
    }

    // ==========================================
    // KROK C: REJESTRACJA W AUDIT LOG
    // ==========================================
    let action = "bootstrap:import";
    let prev_hash_row: Option<String> = AuditQueries::latest_hash_tx(&mut tx).await?;
    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let hash = kms_core::audit::compute_audit_hash(&kms_core::audit::AuditHashInput {
        id: &Uuid::new_v4().to_string(),
        caller_service: &caller_service,
        target_service: "bootstrap",
        action,
        algorithm: "bootstrap-import",
        status: "Success",
        reason: Some(&format!(
            "imported {} total records (resources + credentials)",
            inserted_total
        )),
        prev_hash,
        timestamp: &now,
        request_id: None,
        operation_id: None,
        target_id: None,
        metadata: Some("bootstrap_import_v2"),
    });

    AuditQueries::insert_tx(
        &mut tx,
        kms_db::repositories::AuditInsert {
            id: Uuid::new_v4(),
            caller_service: caller_service.clone(),
            target_service: "bootstrap".to_string(),
            action: action.to_string(),
            algorithm: "bootstrap-import".to_string(),
            status: "Success".to_string(),
            reason: Some(format!("imported {} total records", inserted_total)),
            prev_hash: prev_hash.to_string(),
            hash,
            signature: Some(Vec::<u8>::new()),
            request_id: None,
            operation_id: None,
            target_id: None,
            metadata: Some("bootstrap_import_v2".to_string()),
            created_at: now,
        },
    )
    .await?;

    tx.commit().await?;

    info!(
        total = inserted_total,
        "Successfully committed combined bootstrap transaction"
    );
    Ok(inserted_total)
}
