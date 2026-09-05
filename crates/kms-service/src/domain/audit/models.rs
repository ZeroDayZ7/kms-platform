use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditAction {
    GetPrivateKey,
    GetPublicKey,
    GetSymmetricKey,
    GenerateKey,
    GenerateDataKey,
    EncryptData,
    DecryptData,
    RotateKey,
    RewrapKeys,
    SignData,
    IssueAgentCredential,
    ImportBootstrapCredential,
    CredentialProvisioned,
    CredentialProvisionFailed,
    KeyRotated,
    KeyRevoked,
    KeyExpired,
    SystemStarted,
    SystemShutdown,
    MasterKeyGenerated,
    MasterKeyUnsealed,
    MasterKeySealed,
    MasterKeyOperationFailed,
    AuditVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditStatus {
    Success,
    AccessDenied,
    NotFound,
    ValidationFailure,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: uuid::Uuid,
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub action: AuditAction,
    pub algorithm: KeyAlgorithm,
    pub status: AuditStatus,
    pub reason: Option<String>,
    pub hash_version: String,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub operation_id: String,
    pub nonce: Option<String>,
    pub actor_id: ServiceId,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditLog {
    pub id: uuid::Uuid,
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub action: AuditAction,
    pub algorithm: KeyAlgorithm,
    pub status: AuditStatus,
    pub reason: Option<String>,
    pub prev_hash: Option<String>,
    pub hash_version: String,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalAuditEntry {
    pub id: uuid::Uuid,
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub action: AuditAction,
    pub algorithm: KeyAlgorithm,
    pub status: AuditStatus,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

impl CanonicalAuditEntry {
    pub fn new(
        context: &RequestContext,
        action: AuditAction,
        status: AuditStatus,
        details: Option<serde_json::Value>,
        prev_hash: &str,
    ) -> Self {
        let target = context.actor_id.clone();
        Self {
            id: uuid::Uuid::now_v7(),
            caller_service: context.actor_id.clone(),
            target_service: target,
            action,
            algorithm: KeyAlgorithm::AES256GCM,
            status,
            reason: None,
            prev_hash: prev_hash.to_string(),
            request_id: Some(context.operation_id.clone()),
            operation_id: Some(context.operation_id.clone()),
            target_id: None,
            metadata: Self::sanitize_details(details),
            timestamp: Utc::now(),
        }
    }

    fn canonicalize_value(value: &Value, parent_key: Option<&str>) -> Value {
        match value {
            Value::Object(map) => {
                let mut ordered = BTreeMap::new();
                for (key, inner) in map {
                    let redacted_key = parent_key
                        .map(|parent| format!("{parent}.{key}"))
                        .unwrap_or_else(|| key.clone());
                    ordered.insert(
                        key.clone(),
                        Self::canonicalize_value(inner, Some(&redacted_key)),
                    );
                }
                Value::Object(Map::from_iter(ordered))
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| Self::canonicalize_value(item, parent_key))
                    .collect(),
            ),
            _ => {
                if parent_key.is_some_and(|key| key.to_ascii_lowercase().contains("secret")) {
                    Value::String("[REDACTED]".to_string())
                } else {
                    value.clone()
                }
            }
        }
    }

    pub fn sanitize_details(details: Option<serde_json::Value>) -> Option<serde_json::Value> {
        details.map(|value| Self::canonicalize_value(&value, None))
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        map.insert(
            "action".to_string(),
            Value::String(format!("{:?}", self.action)),
        );
        map.insert(
            "algorithm".to_string(),
            Value::String(format!("{:?}", self.algorithm)),
        );
        map.insert(
            "caller_service".to_string(),
            Value::String(self.caller_service.0.clone()),
        );
        map.insert("id".to_string(), Value::String(self.id.to_string()));
        map.insert(
            "operation_id".to_string(),
            Value::String(self.operation_id.clone().unwrap_or_default()),
        );
        map.insert(
            "hash_version".to_string(),
            Value::String("v1".to_string()),
        );
        map.insert(
            "prev_hash".to_string(),
            Value::String(self.prev_hash.clone()),
        );
        map.insert(
            "reason".to_string(),
            Value::String(self.reason.clone().unwrap_or_default()),
        );
        map.insert(
            "request_id".to_string(),
            Value::String(self.request_id.clone().unwrap_or_default()),
        );
        map.insert(
            "status".to_string(),
            Value::String(format!("{:?}", self.status)),
        );
        map.insert(
            "target_id".to_string(),
            Value::String(self.target_id.clone().unwrap_or_default()),
        );
        map.insert(
            "target_service".to_string(),
            Value::String(self.target_service.0.clone()),
        );
        map.insert(
            "timestamp".to_string(),
            Value::String(
                self.timestamp
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                    .to_string(),
            ),
        );
        map.insert(
            "metadata".to_string(),
            self.metadata.clone().unwrap_or(Value::Null),
        );

        let payload = Value::Object(Map::from_iter(map));
        serde_json::to_string(&payload)
    }

    pub fn hash_chain(&self) -> Result<String, serde_json::Error> {
        let canonical = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

impl AuditLog {
    pub fn sanitize_reason(reason: Option<&str>) -> Option<String> {
        let reason = reason?;
        if reason.trim().is_empty() {
            return None;
        }

        const SENSITIVE_KEYWORDS: &[&str] = &[
            "password",
            "secret",
            "private_key",
            "master_key",
            "kek",
            "dek",
            "pin",
            "passphrase",
            "api_key",
            "hmac",
            "plaintext",
            "bootstrap",
        ];

        let mut sanitized = reason.to_string();
        for &keyword in SENSITIVE_KEYWORDS {
            loop {
                let lower = sanitized.to_ascii_lowercase();
                if let Some(pos) = lower.find(keyword) {
                    let end = pos + keyword.len();
                    sanitized.replace_range(pos..end, "[REDACTED]");
                } else {
                    break;
                }
            }
        }

        if sanitized.is_empty() {
            None
        } else {
            Some(sanitized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_actions_cover_bootstrap_and_startup() {
        let _ = AuditAction::SystemStarted;
        let _ = AuditAction::ImportBootstrapCredential;
        let _ = AuditAction::MasterKeyUnsealed;
        let _ = AuditAction::CredentialProvisioned;
    }

    #[test]
    fn audit_status_uses_non_secret_semantics() {
        let _ = AuditStatus::Success;
        let _ = AuditStatus::AccessDenied;
        let _ = AuditStatus::ValidationFailure;
        let _ = AuditStatus::Failure;
    }

    #[test]
    fn sanitize_reason_strips_secret_like_keywords() {
        let redacted = AuditLog::sanitize_reason(Some("password=secret123 and private_key=abc"));
        assert!(redacted.is_some());
        let value = redacted.unwrap();
        assert!(value.contains("[REDACTED]"));
        assert!(!value.contains("secret123"));
        assert!(!value.contains("private_key"));
    }
}
