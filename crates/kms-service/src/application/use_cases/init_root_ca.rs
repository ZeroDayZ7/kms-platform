use chrono::Utc;
use serde_json::json;
// removed unused import

use crate::{
    errors::{AppError, AppResult},
    server::state::AppState,
};

use kms_db::repositories::{CredentialQueries, RootCaQueries};

use uuid::Uuid;

pub struct InitRootCaInput {
    pub ca_tag: String,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub certificate_pem: String,
    pub serial: String,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<serde_json::Value>,
}

pub struct InitRootCaOutput {
    pub root_ca_id: Uuid,
    pub ceremony_id: Uuid,
}

pub async fn execute(state: &AppState, input: InitRootCaInput) -> AppResult<InitRootCaOutput> {
    // Open transaction
    let mut tx = state.db.begin().await.map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    // Advisory lock to prevent races
    kms_db::repositories::RootCaQueries::advisory_xact_lock_tx(&mut tx, &input.ca_tag)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    // Check exists
    let exists: bool =
        kms_db::repositories::RootCaQueries::exists_by_tag_tx(&mut tx, &input.ca_tag)
            .await
            .map_err(|err| {
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;

    if exists {
        return Err(AppError::ValidationError(format!(
            "Root CA '{}' already exists",
            input.ca_tag
        )));
    }

    // Fetch KEK info
    let kek_row = CredentialQueries::fetch_latest_kek_id(&state.db, "kms-system")
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    let (kek_id, kek_version) = match kek_row {
        Some((id, ver)) => (id, ver),
        None => {
            return Err(AppError::ValidationError(
                "No active KEK found for kms-system".to_string(),
            ));
        }
    };

    // Insert root_ca
    let root_ca_id = Uuid::new_v4();
    let created_at = Utc::now();
    let inserted = RootCaQueries::insert_root_ca(
        &mut tx,
        root_ca_id,
        &input.ca_tag,
        &input.algorithm,
        &input.public_key,
        &input.encrypted_private_key,
        kek_id,
        kek_version,
        &input.certificate_pem,
        &input.serial,
        &input.status,
        created_at,
        input.expires_at,
    )
    .await
    .map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    if !inserted {
        return Err(AppError::ValidationError(
            "Root CA insert conflict".to_string(),
        ));
    }

    // Insert ceremony record
    let ceremony_id = Uuid::new_v4();
    let manifest = serde_json::to_vec(&json!({
        "operation": "ca_init",
        "ca_tag": input.ca_tag,
        "algorithm": input.algorithm,
    }))
    .map_err(|e| AppError::ValidationError(format!("invalid payload: {}", e)))?;

    // Record ceremony as an audit log entry
    {
        // Lock audit chain and compute hash
        kms_db::repositories::AuditQueries::lock_audit_chain_tx(&mut tx)
            .await
            .map_err(|err| {
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;

        let prev_hash = kms_db::repositories::AuditQueries::latest_hash_tx(&mut tx)
            .await
            .map_err(|err| {
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?
            .unwrap_or_else(|| {
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            });

        use base64::Engine;
        let metadata = match std::str::from_utf8(&manifest) {
            Ok(s) => s.to_string(),
            Err(_) => base64::engine::general_purpose::STANDARD.encode(&manifest),
        };

        let algorithm_name = if input.algorithm.trim().is_empty() {
            "ECDSA_P256".to_string()
        } else {
            input.algorithm.clone()
        };

        let audit_id = Uuid::new_v4();
        let now = Utc::now();

        let audit_hash = kms_core::audit::compute_audit_hash(&kms_core::audit::AuditHashInput {
            id: &audit_id.to_string(),
            caller_service: "kms-ceremony-cli",
            target_service: "kms-service",
            action: "ca_init",
            algorithm: &algorithm_name,
            status: "RECORDED",
            reason: None,
            prev_hash: &prev_hash,
            timestamp: &now,
            request_id: None,
            operation_id: Some(&ceremony_id.to_string()),
            target_id: Some(&root_ca_id.to_string()),
            metadata: Some(&metadata),
            hash_version: kms_core::audit::AuditHashVersion::CURRENT,
        });

        let audit_row = kms_db::repositories::AuditInsert {
            id: audit_id,
            caller_service: "kms-ceremony-cli".to_string(),
            target_service: "kms-service".to_string(),
            action: "ca_init".to_string(),
            algorithm: algorithm_name.clone(),
            status: "RECORDED".to_string(),
            reason: None,
            prev_hash: prev_hash.clone(),
            hash: audit_hash,
            signature: None,
            request_id: None,
            operation_id: Some(ceremony_id.to_string()),
            target_id: Some(root_ca_id.to_string()),
            metadata: Some(metadata),
            created_at: now,
        };

        kms_db::repositories::AuditQueries::insert_tx(&mut tx, audit_row)
            .await
            .map_err(|err| {
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;
    }

    tx.commit().await.map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    Ok(InitRootCaOutput {
        root_ca_id,
        ceremony_id,
    })
}
