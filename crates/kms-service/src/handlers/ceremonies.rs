use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::server::state::AppState;
use kms_db::repositories::{AuditQueries, RootCaQueries};

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
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Start a DB transaction
    let mut tx: Transaction<'_, Postgres> = state.db.begin().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db begin error: {}", e),
        )
    })?;

    // If this is a CA init, validate required fields and insert into root_cas
    let ceremony_id = Uuid::new_v4();
    if payload.operation == "ca_init" {
        let ca_tag = payload.ca_tag.clone().ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing ca_tag".to_string(),
            )
        })?;

        // Acquire advisory lock to prevent races
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&ca_tag)
            .execute(&mut *tx)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("lock error: {}", e)))?;

        // Check exists
        let exists: bool = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM root_cas WHERE ca_tag = $1)",
        )
        .bind(&ca_tag)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("exists check: {}", e)))?;

        if exists {
            tx.rollback().await.ok();
            return Err((axum::http::StatusCode::CONFLICT, "Root CA already exists".to_string()));
        }

        let algorithm = payload.algorithm.clone().unwrap_or_else(|| "ECDSA_P256".to_string());
        use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
        use base64::Engine as _;

        let public_key = BASE64_ENGINE.decode(payload.public_key_b64.as_deref().ok_or_else(|| {
            (axum::http::StatusCode::BAD_REQUEST, "missing public_key_b64".to_string())
        })?)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("public key decode: {}", e)))?;

        let encrypted_private_key = BASE64_ENGINE.decode(payload.encrypted_private_key_b64.as_deref().ok_or_else(|| {
            (axum::http::StatusCode::BAD_REQUEST, "missing encrypted_private_key_b64".to_string())
        })?)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("encrypted key decode: {}", e)))?;

        let kek_id = payload.kek_id.ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing kek_id".to_string()))?;
        let kek_version = payload.kek_version.ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing kek_version".to_string()))?;

        let cert_pem = payload.certificate_pem.clone().unwrap_or_default();
        let serial = payload.serial.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
        let status = payload.status.clone().unwrap_or_else(|| "INITIALIZING".to_string());
        let created_at = chrono::Utc::now();

        // Insert root_ca within tx
        let root_ca_id = Uuid::new_v4();
        let inserted = RootCaQueries::insert_root_ca(
            &mut tx,
            root_ca_id,
            &ca_tag,
            &algorithm,
            &public_key,
            &encrypted_private_key,
            kek_id,
            kek_version,
            &cert_pem,
            &serial,
            &status,
            created_at,
            payload.expires_at,
        )
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("insert root_ca: {}", e)))?;

        if !inserted {
            tx.rollback().await.ok();
            return Err((axum::http::StatusCode::CONFLICT, "Root CA insert conflict".to_string()));
        }

        // Insert ceremony record
        let manifest = serde_json::to_vec(&payload).map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid payload: {}", e),
            )
        })?;

        sqlx::query("INSERT INTO ceremonies (id, kind, payload, status, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(ceremony_id)
            .bind("ca_init")
            .bind(&manifest)
            .bind("RECORDED")
            .bind(chrono::Utc::now())
            .execute(&mut *tx)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("insert ceremony: {}", e)))?;

        // Insert audit log (simplified placeholder values)
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
            metadata: payload.metadata.as_ref().map(|v| v.to_string()),
            created_at: chrono::Utc::now(),
        };

        AuditQueries::insert_tx(&mut tx, audit_row)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("audit insert: {}", e)))?;
    } else {
        // Generic ceremony recording for other operations
        let manifest = serde_json::to_vec(&payload).map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid payload: {}", e),
            )
        })?;

        sqlx::query("INSERT INTO ceremonies (id, kind, payload, status, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(ceremony_id)
            .bind(&payload.operation)
            .bind(&manifest)
            .bind("RECORDED")
            .bind(chrono::Utc::now())
            .execute(&mut *tx)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("insert ceremony: {}", e)))?;
    }

    tx.commit().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("tx commit: {}", e),
        )
    })?;

    Ok(Json(serde_json::json!({"ceremony_id": ceremony_id})))
}
