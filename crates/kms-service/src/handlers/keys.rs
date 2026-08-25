use axum::{
    Json,
    extract::{Path, State},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use crate::{
    application::use_cases::{
        GenerateDataKeyInput, GenerateKeyPairInput, GetPublicKeyInput, GetSymmetricKeyInput,
        RotateKeyInput,
    },
    domain::keys::models::{KeyAlgorithm, KeyPurpose, KeyStatus, RotationReason, ServiceId},
    errors::{AppError, AppResult},
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

#[derive(Debug, Deserialize)]
pub struct GenerateKeyRequest {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
}

#[derive(Debug, Deserialize)]
pub struct GenerateDataKeyRequest {
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Serialize)]
pub struct GenerateDataKeyResponse {
    pub algorithm: KeyAlgorithm,
    pub key_version: u32,
    #[serde(rename = "wrapped_dek_b64")]
    pub wrapped_dek_b64: String,
    #[serde(rename = "dek_b64")]
    pub dek_b64: String,
}

#[derive(Debug, Serialize)]
pub struct KeyPairResponse {
    pub id: String,
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    pub public_key_pem: String,
    pub version: u32,
    pub status: KeyStatus,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
    pub reason: RotationReason,
    pub actor_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GetPrivateKeyRequest {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Serialize)]
pub struct PrivateKeyResponse {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
    pub version: u32,
    #[serde(rename = "private_key_b64")]
    pub private_key_b64: String,
}

pub async fn generate_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Json(payload): Json<GenerateKeyRequest>,
) -> AppResult<Json<KeyPairResponse>> {
    let input = GenerateKeyPairInput {
        caller_service: _caller.clone(),
        service_id: ServiceId(payload.service_id),
        algorithm: payload.algorithm,
        purpose: payload.purpose,
    };

    let entity = state.use_cases.generate_key_pair.execute(input).await?;

    Ok(Json(KeyPairResponse {
        id: entity.id.to_string(),
        service_id: entity.service_id.0,
        algorithm: entity.algorithm,
        purpose: entity.purpose,
        public_key_pem: entity.public_key_pem,
        version: entity.version,
        status: entity.status,
        created_at: entity.created_at.to_rfc3339(),
    }))
}

pub async fn generate_data_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<GenerateDataKeyRequest>,
) -> AppResult<Json<GenerateDataKeyResponse>> {
    let output = state
        .use_cases
        .generate_data_key
        .execute(GenerateDataKeyInput {
            caller_service: caller_service.clone(),
            algorithm: payload.algorithm,
        })
        .await?;

    Ok(Json(GenerateDataKeyResponse {
        algorithm: output.algorithm,
        key_version: output.master_key_version as u32,
        wrapped_dek_b64: BASE64.encode(output.wrapped_dek),
        dek_b64: BASE64.encode(output.plaintext_dek.as_bytes()),
    }))
}

pub async fn get_public_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Path((service_id, algorithm)): Path<(String, KeyAlgorithm)>,
) -> AppResult<Json<KeyPairResponse>> {
    let input = GetPublicKeyInput {
        service_id: ServiceId(service_id),
        algorithm,
    };

    let entity = state.use_cases.get_public_key.execute(input).await?;

    Ok(Json(KeyPairResponse {
        id: entity.id.to_string(),
        service_id: entity.service_id.0,
        algorithm: entity.algorithm,
        purpose: entity.purpose,
        public_key_pem: entity.public_key_pem,
        version: entity.version,
        status: entity.status,
        created_at: entity.created_at.to_rfc3339(),
    }))
}

pub async fn rotate_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<RotateKeyRequest>,
) -> AppResult<Json<KeyPairResponse>> {
    let input = RotateKeyInput {
        service_id: ServiceId(payload.service_id),
        caller_service,
        algorithm: payload.algorithm,
        reason: payload.reason,
        actor_id: payload.actor_id,
    };

    let entity = state.use_cases.rotate_key.execute(input).await?;

    Ok(Json(KeyPairResponse {
        id: entity.id.to_string(),
        service_id: entity.service_id.0,
        algorithm: entity.algorithm,
        purpose: entity.purpose,
        public_key_pem: entity.public_key_pem,
        version: entity.version,
        status: entity.status,
        created_at: entity.created_at.to_rfc3339(),
    }))
}

//#region private_key_export_disabled
pub fn private_key_export_disabled() -> AppError {
    AppError::ValidationError(
        "Private key export is disabled for HTTP clients. Use public key, encryption, or signing endpoints instead.".to_string(),
    )
}

pub async fn get_private_key_handler(
    State(_state): State<AppState>,
    AuthenticatedService(_caller_service): AuthenticatedService,
    Json(_payload): Json<GetPrivateKeyRequest>,
) -> AppResult<Json<PrivateKeyResponse>> {
    Err(private_key_export_disabled())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //#region private_key_export_is_disabled
    fn private_key_export_is_disabled() {
        let err = private_key_export_disabled();
        assert!(
            matches!(err, AppError::ValidationError(message) if message.contains("Private key export is disabled"))
        );
    }

    #[test]
    fn generate_data_key_contract_serializes_expected_fields() {
        let json = r#"{ "algorithm": "AES256GCM" }"#;
        let req: GenerateDataKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.algorithm, KeyAlgorithm::AES256GCM);

        let response = GenerateDataKeyResponse {
            algorithm: KeyAlgorithm::AES256GCM,
            key_version: 1,
            wrapped_dek_b64: "AQID".to_string(),
            dek_b64: "BAUG".to_string(),
        };

        let serialized = serde_json::to_value(response).unwrap();
        assert_eq!(serialized["algorithm"], "AES256GCM");
        assert_eq!(serialized["key_version"], 1);
    }
}

// ============================================================================
// STRUCTS & HANDLER FOR SYMMETRIC KEYS
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GetSymmetricKeyRequest {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Serialize)]
pub struct SymmetricKeyResponse {
    pub service_id: String,
    pub algorithm: KeyAlgorithm,
    pub version: u32,
    #[serde(rename = "key_b64")]
    pub key_b64: String,
}

pub async fn get_symmetric_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<GetSymmetricKeyRequest>,
) -> AppResult<Json<SymmetricKeyResponse>> {
    let input = GetSymmetricKeyInput {
        caller_service,
        target_service: ServiceId(payload.service_id),
        algorithm: payload.algorithm,
    };

    let output = state.use_cases.get_symmetric_key.execute(input).await?;

    Ok(Json(SymmetricKeyResponse {
        service_id: output.service_id.0,
        algorithm: output.algorithm,
        version: output.version,
        key_b64: BASE64.encode(output.key_bytes),
    }))
}
