// src/domain/audit/models.rs
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    GetPrivateKey,
    GetPublicKey,
    GetSymmetricKey,
    GenerateKey,
    GenerateDataKey,
    RotateKey,
    RewrapKeys,
    SignData,
    KeyRotated,
    KeyRevoked,
    KeyExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStatus {
    Success,
    AccessDenied,
    NotFound,
    Failure,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    #[serde(with = "bson::serde_helpers::uuid_1_as_binary")]
    pub id: uuid::Uuid,
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub action: AuditAction,
    pub algorithm: KeyAlgorithm,
    pub status: AuditStatus,
    pub reason: Option<String>,

    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub timestamp: DateTime<Utc>,
}
