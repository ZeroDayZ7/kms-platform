use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};

use crate::{
    application::use_cases::{
        GenerateKeyPairInput, GetPrivateKeyInput, GetPublicKeyInput, GetSymmetricKeyInput,
        RotateKeyInput,
    },
    domain::keys::models::{KeyAlgorithm, KeyPurpose, KeyStatus, RotationReason, ServiceId},
    errors::AppResult,
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
    #[serde(with = "serde_bytes")] // Base64 dla Go []byte
    pub private_key_bytes: Vec<u8>,
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

pub async fn get_private_key_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller_service): AuthenticatedService,
    Json(payload): Json<GetPrivateKeyRequest>,
) -> AppResult<Json<PrivateKeyResponse>> {
    let input = GetPrivateKeyInput {
        caller_service,
        target_service: ServiceId(payload.service_id),
        algorithm: payload.algorithm,
    };

    let output = state.use_cases.get_private_key.execute(input).await?;

    Ok(Json(PrivateKeyResponse {
        service_id: output.service_id.0,
        algorithm: output.algorithm,
        version: output.version,
        private_key_bytes: output.private_key_bytes,
    }))
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
    #[serde(with = "serde_bytes")] // Base64 dla Go []byte
    pub key_bytes: Vec<u8>,
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
        key_bytes: output.key_bytes,
    }))
}
