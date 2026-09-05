use std::sync::Arc;

use serde_json::json;

use crate::{
    config::acl::{CompiledAcl, KeyAccessLevel, authorize_key_access},
    domain::{
        audit::{
            models::{AuditAction, RequestContext},
            service::AuditService,
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
    A: crate::domain::audit::repository::AuditRepository,
{
    audit_service: Arc<AuditService<A>>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    acl_policy: Arc<CompiledAcl>,
}

impl<A> GenerateDataKeyUseCase<A>
where
    A: crate::domain::audit::repository::AuditRepository,
{
    pub fn new(
        audit_service: Arc<AuditService<A>>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            audit_service,
            crypto_service,
            acl_policy,
        }
    }

    pub async fn execute(
        &self,
        ctx: &RequestContext,
        input: GenerateDataKeyInput,
    ) -> AppResult<GenerateDataKeyOutput> {
        let target_service = input.caller_service.clone();
        let is_allowed = authorize_key_access(
            &self.acl_policy,
            &input.caller_service,
            &target_service,
            input.algorithm,
            KeyAccessLevel::GenerateDataKey,
        );

        if !is_allowed {
            self.audit_service
                .record_access_denied(
                    ctx,
                    AuditAction::GenerateDataKey,
                    "ACL Policy Violation for GenerateDataKey",
                )
                .await?;

            return Err(AppError::Unauthorized);
        }

        if input.algorithm != KeyAlgorithm::AES256GCM {
            self.audit_service
                .record_validation_failure(
                    ctx,
                    AuditAction::GenerateDataKey,
                    "Only AES256GCM is supported",
                )
                .await?;

            return Err(AppError::ValidationError(
                "Only AES256GCM is supported for GenerateDataKey".to_string(),
            ));
        }

        let generated = self
            .crypto_service
            .generate_data_key(input.algorithm)
            .await?;

        self.audit_service
            .record_success(
                ctx,
                AuditAction::GenerateDataKey,
                Some(json!({
                    "target_service": target_service.0,
                    "algorithm": input.algorithm,
                    "master_key_version": generated.master_key_version,
                    "wrapped_len": generated.wrapped.len()
                })),
            )
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
