use axum::{Json, extract::State};
use serde::Deserialize;

use crate::application::use_cases::init_root_ca::{
    InitRootCaInput, execute as init_root_ca_execute,
};
use crate::errors::AppError;
use crate::server::state::AppState;

#[derive(Deserialize)]
pub struct LoadCaRequest {
    pub ca_tag: String,
    pub encrypted_private_key_b64: Option<String>,
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
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
    // Determine encrypted blob: prefer provided payload, otherwise fetch from DB
    let encrypted: Vec<u8> = if let Some(ref b64) = payload.encrypted_private_key_b64 {
        BASE64_ENGINE
            .decode(b64)
            .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("invalid base64: {}", e)))?
    } else {
        // Fetch from DB
        match kms_db::repositories::RootCaQueries::fetch_active_by_tag(&state.db, &payload.ca_tag)
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db error: {}", e),
                )
            })?
        {
            Some(row) => row.encrypted_private_key,
            None => {
                return Err((
                    axum::http::StatusCode::NOT_FOUND,
                    format!("root CA not found for tag '{}'", payload.ca_tag),
                ))
            }
        }
    };

    crate::hsm::client::load_root_ca(socket, &payload.ca_tag, &encrypted, None)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("hsm error: {}", e)))?;

    Ok(Json(serde_json::json!({"status": "loaded"})))
}

#[derive(Deserialize)]
pub struct CaInitRequest {
    pub ca_tag: String,
    pub algorithm: Option<String>,
    pub public_key_b64: String,
    pub encrypted_private_key_b64: String,
    pub certificate_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn post_ca_init(
    State(state): State<AppState>,
    Json(payload): Json<CaInitRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;

    let public_key = BASE64_ENGINE.decode(&payload.public_key_b64).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("invalid base64 public key: {}", e),
        )
    })?;

    let encrypted_private_key = BASE64_ENGINE
        .decode(&payload.encrypted_private_key_b64)
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid base64 encrypted key: {}", e),
            )
        })?;

    let algorithm = payload
        .algorithm
        .clone()
        .unwrap_or_else(|| "ECDSA_P256".to_string());
    let cert_pem = payload.certificate_pem.clone().unwrap_or_default();
    let serial = uuid::Uuid::new_v4().to_string();
    let status = "INITIALIZING".to_string();

    let input = InitRootCaInput {
        ca_tag: payload.ca_tag.clone(),
        algorithm,
        public_key,
        encrypted_private_key,
        certificate_pem: cert_pem,
        serial,
        status,
        expires_at: payload.expires_at,
        metadata: payload.metadata.clone(),
    };

    match init_root_ca_execute(&state, input).await {
        Ok(output) => Ok(Json(
            serde_json::json!({"root_ca_id": output.root_ca_id, "ceremony_id": output.ceremony_id}),
        )),
        Err(e) => match e {
            AppError::ValidationError(msg) => Err((axum::http::StatusCode::CONFLICT, msg)),
            _ => Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("server error: {}", e),
            )),
        },
    }
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
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("hsm client error: {}", e),
            )
        })?;

    match resp {
        kms_core::hsm::protocol::HsmResponse::SignedIntermediate { certificate_pem } => Ok(Json(
            serde_json::json!({"status": "ok", "certificate_pem": certificate_pem}),
        )),
        kms_core::hsm::protocol::HsmResponse::Error { code, message } => Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("hsm error {}: {}", code, message),
        )),
        other => Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("unexpected hsm response: {:?}", other),
        )),
    }
}
