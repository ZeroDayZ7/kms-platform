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

#[derive(Debug, serde::Deserialize)]
pub struct ImportBootstrapRequest {
    pub version: u32,
    pub credentials: Vec<serde_json::Value>,
}

pub async fn import_bootstrap_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<ImportBootstrapRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Map incoming JSON values into domain input (use serde::from_value in use-case)
    let input = ImportBootstrapInput {
        version: payload.version,
        credentials: payload.credentials,
    };

    let count = import_bootstrap(state.clone(), caller.0, input).await?;

    Ok(Json(serde_json::json!({"imported": count})))
}
