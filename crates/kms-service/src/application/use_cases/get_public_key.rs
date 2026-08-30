// src/application/use_cases/get_public_key.rs
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
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
    A: AuditRepository + Send + Sync,
{
    key_repo: Arc<R>,
    audit_repo: Arc<A>,
}

impl<R, A> GetPublicKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    //#region new
    pub fn new(key_repo: Arc<R>, audit_repo: Arc<A>) -> Self {
        Self {
            key_repo,
            audit_repo,
        }
    }

    pub async fn execute(&self, input: GetPublicKeyInput) -> AppResult<KeyPairEntity> {
        let now = chrono::Utc::now();
        let key = self
            .key_repo
            .get_active_or_valid_deprecated_key(&input.service_id, input.algorithm, now)
            .await?;

        match key {
            Some(k) => {
                self.audit_repo
                    .record(AuditLog {
                        id: Uuid::now_v7(),
                        caller_service: input.service_id.clone(),
                        target_service: input.service_id.clone(),
                        action: AuditAction::GetPublicKey,
                        algorithm: input.algorithm,
                        status: AuditStatus::Success,
                        reason: None,
                        request_id: None,
                        operation_id: None,
                        target_id: Some(input.service_id.0.clone()),
                        metadata: Some("public_key_retrieved".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;
                Ok(k)
            }
            None => {
                self.audit_repo
                    .record(AuditLog {
                        id: Uuid::now_v7(),
                        caller_service: input.service_id.clone(),
                        target_service: input.service_id.clone(),
                        action: AuditAction::GetPublicKey,
                        algorithm: input.algorithm,
                        status: AuditStatus::NotFound,
                        reason: AuditLog::sanitize_reason(Some(
                            "No active or valid deprecated public key found",
                        )),
                        request_id: None,
                        operation_id: None,
                        target_id: Some(input.service_id.0.clone()),
                        metadata: Some("key_missing".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;
                Err(AppError::NotFound(format!(
                    "No active or valid deprecated public key found for service '{}' with algorithm '{:?}'",
                    input.service_id.0, input.algorithm
                )))
            }
        }
    }
}
