use crate::domain::crypto::EncryptedPrivateKey;
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use crate::errors::{AppError, AppResult};
use crate::server::{extractors::authenticated_service::AuthenticatedService, state::AppState};
use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EncryptRequest {
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub master_key_version: i32,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub master_key_version: i32,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct SignDataRequest {
    pub target_service: String,
    pub algorithm: KeyAlgorithm,
    pub payload_b64: String,
    pub key_version: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SignDataResponse {
    pub signature_b64: String,
    pub key_version: u32,
    pub algorithm: KeyAlgorithm,
}

pub async fn encrypt_handler(
    State(state): State<AppState>,
    Json(payload): Json<EncryptRequest>,
) -> AppResult<Json<EncryptResponse>> {
    let encrypted = state
    .use_cases
    .encrypt_data
    .execute(&payload.plaintext)
    .await?;

    Ok(Json(EncryptResponse {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        master_key_version: encrypted.master_key_version,
    }))
}

pub async fn decrypt_handler(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> AppResult<Json<DecryptResponse>> {
    let payload_struct = EncryptedPrivateKey {
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        master_key_version: payload.master_key_version,
    };

    let decrypted = state
    .use_cases
    .decrypt_data
    .execute(&payload_struct)
    .await?;

    Ok(Json(DecryptResponse {
        plaintext: decrypted,
    }))
}

pub async fn sign_data_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<SignDataRequest>,
) -> AppResult<Json<SignDataResponse>> {
    let payload_bytes = BASE64
        .decode(&payload.payload_b64)
        .map_err(|e| AppError::ValidationError(format!("Invalid payload_b64: {e}")))?;

    let input = crate::application::use_cases::sign_data::SignDataInput {
        caller_service,
        target_service: ServiceId(payload.target_service),
        algorithm: payload.algorithm,
        payload: payload_bytes,
        key_version: payload.key_version,
    };

    let output = state.use_cases.sign_data.execute(input).await?;

    Ok(Json(SignDataResponse {
        signature_b64: BASE64.encode(output.signature_bytes),
        key_version: output.key_version,
        algorithm: output.algorithm,
    }))
}
