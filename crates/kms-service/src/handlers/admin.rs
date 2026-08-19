use axum::{Json, extract::State};
use serde::Deserialize;

use crate::{
    application::use_cases::rewrap_keys::{RewrapKeysInput, rewrap_keys},
    errors::{AppError, AppResult},
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

use crate::bootstrap::recover_storage_key_from_shares;

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub shares: Vec<String>,
}

pub async fn unlock_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Json(payload): Json<UnlockRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // read manifest from working directory
    let manifest_path = std::path::Path::new("ceremony_manifest.json");

    let recovered = recover_storage_key_from_shares(manifest_path, &payload.shares)
        .map_err(|e| AppError::RuntimeError(format!("Failed to recover storage key: {}", e)))?;

    // store into application state
    state.set_storage_key(recovered).await;

    // After unlocking, bootstrap keys that may be missing
    crate::bootstrap::bootstrap_keys(
        &state.settings.acl,
        state.key_repo.clone(),
        state.crypto_service.clone(),
    )
    .await?;

    Ok(Json(serde_json::json!({ "status": "READY" })))
}

pub async fn lock_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
) -> AppResult<Json<serde_json::Value>> {
    state.clear_storage_key().await;
    Ok(Json(serde_json::json!({ "status": "LOCKED" })))
}

#[derive(Debug, Deserialize)]
pub struct RewrapKeysRequest {
    pub target_version: i32,
    pub batch_size: usize,
}

pub async fn rewrap_keys_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Json(payload): Json<RewrapKeysRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let count = rewrap_keys(
        state.key_repo.clone(),
        state.crypto_service.clone(),
        RewrapKeysInput {
            target_master_version: payload.target_version,
            batch_size: payload.batch_size,
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "rewrapped": count,
        "target_version": payload.target_version,
        "batch_size": payload.batch_size,
    })))
}
