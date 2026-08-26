use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    config::acl::{CompiledAcl, KeyAccessLevel, authorize_key_access},
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
        },
        crypto::{KeyAlgorithm, KmsCryptoService, SecretBytes},
        keys::models::ServiceId,
    },
    errors::{AppError, AppResult},
};

#[derive(Debug, Clone)]
pub struct GenerateDataKeyInput {
    pub caller_service: ServiceId,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Clone)]
pub struct GenerateDataKeyOutput {
    pub caller_service: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub plaintext_dek: SecretBytes,
    pub wrapped_dek: Vec<u8>,
    pub master_key_version: i32,
}

pub struct GenerateDataKeyUseCase<A>
where
    A: AuditRepository,
{
    audit_repo: Arc<A>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    acl_policy: Arc<CompiledAcl>,
}

impl<A> GenerateDataKeyUseCase<A>
where
    A: AuditRepository,
{
    pub fn new(
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            audit_repo,
            crypto_service,
            acl_policy,
        }
    }

    pub async fn execute(&self, input: GenerateDataKeyInput) -> AppResult<GenerateDataKeyOutput> {
        let target_service = input.caller_service.clone();
        let is_allowed = authorize_key_access(
            &self.acl_policy,
            &input.caller_service,
            &target_service,
            input.algorithm,
            KeyAccessLevel::GenerateDataKey,
        );

        if !is_allowed {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: target_service.clone(),
                    action: AuditAction::GenerateDataKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::AccessDenied,
                    reason: Some("ACL Policy Violation for GenerateDataKey".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::Unauthorized);
        }

        if input.algorithm != KeyAlgorithm::AES256GCM {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: target_service.clone(),
                    action: AuditAction::GenerateDataKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::Error("Unsupported algorithm".to_string()),
                    reason: Some("Only AES256GCM is supported".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::ValidationError(
                "Only AES256GCM is supported for GenerateDataKey".to_string(),
            ));
        }

        let generated = self
            .crypto_service
            .generate_data_key(input.algorithm)
            .await?;

        self.audit_repo
            .record(AuditLog {
                id: Uuid::now_v7(),
                caller_service: input.caller_service.clone(),
                target_service: target_service.clone(),
                action: AuditAction::GenerateDataKey,
                algorithm: input.algorithm,
                status: AuditStatus::Success,
                reason: None,
                timestamp: Utc::now(),
            })
            .await?;

        Ok(GenerateDataKeyOutput {
            caller_service: input.caller_service,
            algorithm: generated.algorithm,
            plaintext_dek: generated.plaintext,
            wrapped_dek: generated.wrapped,
            master_key_version: generated.master_key_version,
        })
    }
}
