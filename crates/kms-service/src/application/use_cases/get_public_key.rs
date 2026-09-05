// src/application/use_cases/get_public_key.rs
use std::sync::Arc;

use serde_json::json;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, RequestContext},
            service::AuditService,
        },
        keys::{
            models::{KeyAlgorithm, KeyPairEntity, ServiceId},
            repository::KeyRepository,
        },
    },
    errors::{AppError, AppResult},
};

pub struct GetPublicKeyInput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
}

pub struct GetPublicKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: crate::domain::audit::repository::AuditRepository + Send + Sync,
{
    key_repo: Arc<R>,
    audit_service: Arc<AuditService<A>>,
}

impl<R, A> GetPublicKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: crate::domain::audit::repository::AuditRepository + Send + Sync,
{
    pub fn new(key_repo: Arc<R>, audit_service: Arc<AuditService<A>>) -> Self {
        Self {
            key_repo,
            audit_service,
        }
    }

    pub async fn execute(
        &self,
        ctx: &RequestContext,
        input: GetPublicKeyInput,
    ) -> AppResult<KeyPairEntity> {
        let now = chrono::Utc::now();
        let key = self
            .key_repo
            .get_active_or_valid_deprecated_key(&input.service_id, input.algorithm, now)
            .await?;

        match key {
            Some(k) => {
                self.audit_service
                    .record_success(
                        ctx,
                        AuditAction::GetPublicKey,
                        Some(json!({
                            "service_id": input.service_id.0,
                            "algorithm": input.algorithm,
                            "key_version": k.version
                        })),
                    )
                    .await?;
                Ok(k)
            }
            None => {
                self.audit_service
                    .record_validation_failure(
                        ctx,
                        AuditAction::GetPublicKey,
                        "No active or valid deprecated public key found",
                    )
                    .await?;
                Err(AppError::NotFound(format!(
                    "No active or valid deprecated public key found for service '{}' with algorithm '{:?}'",
                    input.service_id.0, input.algorithm
                )))
            }
        }
    }
}
