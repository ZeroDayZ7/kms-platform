use chrono::Utc;
use serde_json::json;
use sqlx::Postgres;

use crate::{
    errors::{AppError, AppResult},
    server::state::AppState,
};

use kms_db::repositories::{AuditQueries, CredentialQueries, RootCaQueries};

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

    // Use repository to insert ceremony within transaction
    kms_db::repositories::ceremonies::CeremonyQueries::insert_tx(
        &mut tx,
        ceremony_id,
        "ca_init",
        &manifest,
        "RECORDED",
        Utc::now(),
    )
    .await
    .map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    // Insert audit
    let audit_row = kms_db::repositories::AuditInsert {
        id: Uuid::new_v4(),
        caller_service: "kms-ceremony-cli".to_string(),
        target_service: "kms-service".to_string(),
        action: "ca_init".to_string(),
        algorithm: "NONE".to_string(),
        status: "RECORD".to_string(),
        reason: None,
        prev_hash: "".to_string(),
        hash: "".to_string(),
        signature: None,
        request_id: None,
        operation_id: Some(ceremony_id.to_string()),
        target_id: Some(root_ca_id.to_string()),
        metadata: None,
        created_at: Utc::now(),
    };

    AuditQueries::insert_tx(&mut tx, audit_row)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    tx.commit().await.map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    Ok(InitRootCaOutput {
        root_ca_id,
        ceremony_id,
    })
}
