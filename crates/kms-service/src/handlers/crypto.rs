use crate::domain::crypto::EncryptedPrivateKey;
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use crate::errors::{AppError, AppResult};
use crate::server::{extractors::authenticated_service::AuthenticatedService, state::AppState};
use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

fn decode_base64_payload(value: &str, field_name: &str) -> Result<Vec<u8>, AppError> {
    BASE64.decode(value).map_err(|e| {
        AppError::ValidationError(format!("INVALID_BASE64_PAYLOAD: {field_name}: {e}"))
    })
}

fn encode_base64_payload(value: &[u8]) -> String {
    BASE64.encode(value)
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    #[serde(rename = "plaintext")]
    pub plaintext_b64: String,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    #[serde(rename = "ciphertext")]
    pub ciphertext_b64: String,
    pub master_key_version: i32,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    #[serde(rename = "ciphertext")]
    pub ciphertext_b64: String,
    pub master_key_version: i32,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    #[serde(rename = "plaintext")]
    pub plaintext_b64: String,
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
    let plaintext = decode_base64_payload(&payload.plaintext_b64, "plaintext")?;
    let encrypted = state.use_cases.encrypt_data.execute(&plaintext).await?;

    Ok(Json(EncryptResponse {
        ciphertext_b64: encode_base64_payload(&encrypted.ciphertext),
        master_key_version: encrypted.master_key_version,
    }))
}

pub async fn decrypt_handler(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> AppResult<Json<DecryptResponse>> {
    let ciphertext = decode_base64_payload(&payload.ciphertext_b64, "ciphertext")?;
    let payload_struct = EncryptedPrivateKey {
        ciphertext,
        master_key_version: payload.master_key_version,
    };

    let decrypted = state.use_cases.decrypt_data.execute(&payload_struct).await?;

    Ok(Json(DecryptResponse {
        plaintext_b64: encode_base64_payload(&decrypted),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_base64_payload_accepts_valid_string() {
        let decoded = decode_base64_payload("aGVsbG8=", "plaintext").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn decode_base64_payload_rejects_invalid_string() {
        let err = decode_base64_payload("%%%invalid%%%", "plaintext").unwrap_err();
        assert!(matches!(err, AppError::ValidationError(message) if message.starts_with("INVALID_BASE64_PAYLOAD")));
    }
}
