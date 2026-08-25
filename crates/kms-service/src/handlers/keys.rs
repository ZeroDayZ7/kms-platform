use axum::{
    Json,
    extract::{Path, State},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    application::use_cases::{
        GenerateKeyPairInput, GetPublicKeyInput, GetSymmetricKeyInput, RotateKeyInput,
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
    fn generate_data_key_request_accepts_aes256gcm_only() {
        let req = serde_json::from_str::<GenerateDataKeyRequest>(r#"{"algorithm":"AES256GCM"}"#)
            .expect("valid request should deserialize");

        assert_eq!(req.algorithm, KeyAlgorithm::AES256GCM);
    }

    #[test]
    fn generate_data_key_rejects_non_aes256gcm_algorithm() {
        let err = serde_json::from_str::<GenerateDataKeyRequest>(r#"{"algorithm":"Ed25519"}"#)
            .expect_err("invalid algorithm should be rejected at deserialization time");

        let message = err.to_string();
        assert!(message.contains("Only AES256GCM is supported"));
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

fn deserialize_generate_data_key_algorithm<'de, D>(
    deserializer: D,
) -> Result<KeyAlgorithm, D::Error>
where
    D: Deserializer<'de>,
{
    let algorithm = KeyAlgorithm::deserialize(deserializer)?;
    if algorithm == KeyAlgorithm::AES256GCM {
        Ok(algorithm)
    } else {
        Err(serde::de::Error::custom(
            "Only AES256GCM is supported for /api/v1/keys/generate-data-key",
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct GenerateDataKeyRequest {
    #[serde(deserialize_with = "deserialize_generate_data_key_algorithm")]
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Serialize)]
pub struct GenerateDataKeyResponse {
    pub algorithm: KeyAlgorithm,
    #[serde(rename = "plaintext_dek_b64")]
    pub plaintext_dek_b64: String,
    #[serde(rename = "wrapped_dek_b64")]
    pub wrapped_dek_b64: String,
    pub master_key_version: i32,
}

pub async fn generate_data_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<GenerateDataKeyRequest>,
) -> AppResult<Json<GenerateDataKeyResponse>> {
    if payload.algorithm != KeyAlgorithm::AES256GCM {
        return Err(AppError::ValidationError(
            "Only AES256GCM is supported for /api/v1/keys/generate-data-key".to_string(),
        ));
    }

    let output = state
        .use_cases
        .generate_data_key
        .execute(crate::application::use_cases::GenerateDataKeyInput {
            caller_service,
            algorithm: payload.algorithm,
        })
        .await?;

    Ok(Json(GenerateDataKeyResponse {
        algorithm: output.algorithm,
        plaintext_dek_b64: BASE64.encode(output.plaintext_dek.as_bytes()),
        wrapped_dek_b64: BASE64.encode(output.wrapped_dek),
        master_key_version: output.master_key_version,
    }))
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
