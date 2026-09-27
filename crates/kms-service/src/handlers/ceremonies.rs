use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::server::state::AppState;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use kms_core::audit::{self as core_audit, AuditHashVersion};
use kms_db::repositories::{AuditInsert, AuditQueries};

#[derive(Deserialize, Serialize)]
pub struct CeremonyRequest {
    pub operation: String,
    // For CA init
    pub ca_tag: Option<String>,
    pub algorithm: Option<String>,
    pub public_key_b64: Option<String>,
    pub encrypted_private_key_b64: Option<String>,
    pub kek_id: Option<Uuid>,
    pub kek_version: Option<i32>,
    pub certificate_pem: Option<String>,
    pub serial: Option<String>,
    pub status: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn register_ceremony_handler(
    State(state): State<AppState>,
    Json(payload): Json<CeremonyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Only generic ceremony handling belongs here. CA init is handled in handlers/ca.rs use case.
    let ceremony_id = Uuid::new_v4();
    let manifest = serde_json::to_vec(&payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid payload: {}", e)))?;

    let mut tx: Transaction<'_, Postgres> = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db begin error: {}", e),
        )
    })?;

    // Append an audit log entry representing the ceremony
    AuditQueries::lock_audit_chain_tx(&mut tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("lock audit chain: {}", e),
            )
        })?;

    let prev_hash = AuditQueries::latest_hash_tx(&mut tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("latest_hash: {}", e),
            )
        })?
        .unwrap_or_default();

    let metadata_str = match std::str::from_utf8(manifest.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => BASE64_ENGINE.encode(manifest.as_slice()),
    };

    let audit_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();

    let hash = core_audit::compute_audit_hash(&core_audit::AuditHashInput {
        id: &audit_id.to_string(),
        caller_service: "kms-service",
        target_service: "ceremony",
        action: &payload.operation,
        algorithm: "NONE",
        status: "RECORDED",
        reason: None,
        prev_hash: &prev_hash,
        timestamp: &now,
        request_id: None,
        operation_id: Some(&ceremony_id.to_string()),
        target_id: None,
        metadata: Some(&metadata_str),
        hash_version: AuditHashVersion::CURRENT,
    });

    let audit_row = AuditInsert {
        id: audit_id,
        caller_service: "kms-service".to_string(),
        target_service: "ceremony".to_string(),
        action: payload.operation.clone(),
        algorithm: "NONE".to_string(),
        status: "RECORDED".to_string(),
        reason: None,
        prev_hash: prev_hash.clone(),
        hash,
        signature: Some(Vec::new()),
        request_id: None,
        operation_id: Some(ceremony_id.to_string()),
        target_id: None,
        metadata: Some(metadata_str),
        created_at: now,
    };

    AuditQueries::insert_tx(&mut tx, audit_row)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("insert audit: {}", e),
            )
        })?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("tx commit: {}", e),
        )
    })?;

    Ok(Json(serde_json::json!({"ceremony_id": ceremony_id})))
}
