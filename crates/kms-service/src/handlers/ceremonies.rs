use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::server::state::AppState;
use kms_db::repositories::ceremonies::CeremonyQueries;

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

    CeremonyQueries::insert_tx(
        &mut tx,
        ceremony_id,
        &payload.operation,
        manifest.as_slice(),
        "RECORDED",
        chrono::Utc::now(),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("insert ceremony: {}", e),
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
