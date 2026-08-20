use axum::{Json, extract::State};
use serde::Deserialize;

use crate::{
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
