use axum::{extract::State, Json};
use serde::Deserialize;

use crate::server::state::AppState;

#[derive(Deserialize)]
pub struct LoadCaRequest {
    pub ca_tag: String,
    pub encrypted_private_key_b64: String,
}

#[derive(Deserialize)]
pub struct SignIntermediateRequest {
    pub ca_tag: String,
    pub csr_pem: String,
    pub validity_days: u32,
}

pub async fn post_ca_load(
    State(state): State<AppState>,
    Json(payload): Json<LoadCaRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let socket = &state.settings.crypto.hsm_socket_path;
    use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
    use base64::Engine as _;

    let encrypted = BASE64_ENGINE.decode(&payload.encrypted_private_key_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("invalid base64: {}", e)))?;

    crate::hsm::client::load_root_ca(socket, &payload.ca_tag, &encrypted, None)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("hsm error: {}", e)))?;

    Ok(Json(serde_json::json!({"status": "loaded"})))
}

pub async fn post_sign_intermediate(
    State(state): State<AppState>,
    Json(payload): Json<SignIntermediateRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let socket = &state.settings.crypto.hsm_socket_path;

    let req = kms_core::hsm::protocol::HsmRequest::SignIntermediateCa {
        ca_tag: payload.ca_tag.clone(),
        csr_pem: payload.csr_pem.clone(),
        validity_days: payload.validity_days,
    };

    let resp = crate::hsm::client::send_hsm_request(socket, &req, None)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("hsm client error: {}", e)))?;

    match resp {
        kms_core::hsm::protocol::HsmResponse::SignedIntermediate { certificate_pem } => {
            Ok(Json(serde_json::json!({"status": "ok", "certificate_pem": certificate_pem})))
        }
        kms_core::hsm::protocol::HsmResponse::Error { code, message } => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("hsm error {}: {}", code, message))),
        other => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("unexpected hsm response: {:?}", other))),
    }
}
