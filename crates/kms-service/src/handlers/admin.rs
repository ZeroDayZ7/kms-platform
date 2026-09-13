use axum::{Json, extract::State};
use serde::Deserialize;

use crate::{
    application::use_cases::import_bootstrap::{ImportBootstrapInput, import_bootstrap},
    application::use_cases::rewrap_keys::{RewrapKeysInput, rewrap_keys},
    errors::AppResult,
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

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

pub async fn import_bootstrap_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<ImportBootstrapInput>,
) -> AppResult<Json<serde_json::Value>> {
    let summary = import_bootstrap(state.clone(), caller.0, payload).await?;

    Ok(Json(serde_json::json!({
        "total_in_file": summary.total_in_file,
        "resources_imported": summary.resources_imported,
        "resources_skipped": summary.resources_skipped,
        "credentials_imported": summary.credentials_imported,
        "credentials_skipped": summary.credentials_skipped,
        "message": summary.message,
    })))
}
