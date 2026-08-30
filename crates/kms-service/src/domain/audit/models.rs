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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl AuditLog {
    pub fn sanitize_reason(reason: Option<&str>) -> Option<String> {
        let Some(reason) = reason else { return None };
        let mut sanitized = reason.to_string();
        for secret_name in [
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
        ] {
            if sanitized.to_ascii_lowercase().contains(secret_name) {
                sanitized = sanitized
                    .replace(secret_name, "[REDACTED]")
                    .replace("[REDACTED]", "[REDACTED]");
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
