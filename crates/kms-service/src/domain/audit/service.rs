use std::sync::Arc;

use serde_json::Value;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus, CanonicalAuditEntry, RequestContext},
            repository::AuditRepository,
        },
        keys::models::KeyAlgorithm,
    },
    errors::AppResult,
};

#[derive(Debug, Clone)]
pub struct AuditService<A> {
    repo: Arc<A>,
}

impl<A> AuditService<A>
where
    A: AuditRepository,
{
    pub fn new(repo: Arc<A>) -> Self {
        Self { repo }
    }

    async fn record_internal(
        &self,
        ctx: &RequestContext,
        action: AuditAction,
        status: AuditStatus,
        details: Option<Value>,
        reason: Option<String>,
        algorithm: KeyAlgorithm,
    ) -> AppResult<()> {
        let prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let entry = CanonicalAuditEntry::new(ctx, action, status, details, prev_hash);

        let audit_log = AuditLog {
            id: entry.id,
            caller_service: entry.caller_service,
            target_service: entry.target_service,
            action: entry.action,
            algorithm,
            status: entry.status,
            reason: reason.or(entry.reason),
            request_id: entry.request_id,
            operation_id: entry.operation_id,
            target_id: entry.target_id,
            metadata: entry
                .metadata
                .map(|value| serde_json::to_string(&value).unwrap_or_default()),
            timestamp: entry.timestamp,
        };

        self.repo.record(audit_log).await
    }

    pub async fn record_success(
        &self,
        ctx: &RequestContext,
        action: AuditAction,
        details: Option<Value>,
    ) -> AppResult<()> {
        self.record_internal(
            ctx,
            action,
            AuditStatus::Success,
            details,
            None,
            KeyAlgorithm::AES256GCM,
        )
        .await
    }

    pub async fn record_failure(
        &self,
        ctx: &RequestContext,
        action: AuditAction,
        reason: String,
    ) -> AppResult<()> {
        let sanitized = AuditLog::sanitize_reason(Some(&reason));
        self.record_internal(
            ctx,
            action,
            AuditStatus::Failure,
            Some(Value::String(reason)),
            sanitized,
            KeyAlgorithm::AES256GCM,
        )
        .await
    }

    pub async fn record_access_denied(
        &self,
        ctx: &RequestContext,
        action: AuditAction,
        reason: &str,
    ) -> AppResult<()> {
        let sanitized = AuditLog::sanitize_reason(Some(reason));
        self.record_internal(
            ctx,
            action,
            AuditStatus::AccessDenied,
            Some(Value::String(reason.to_string())),
            sanitized,
            KeyAlgorithm::AES256GCM,
        )
        .await
    }

    pub async fn record_validation_failure(
        &self,
        ctx: &RequestContext,
        action: AuditAction,
        reason: &str,
    ) -> AppResult<()> {
        let sanitized = AuditLog::sanitize_reason(Some(reason));
        self.record_internal(
            ctx,
            action,
            AuditStatus::ValidationFailure,
            Some(Value::String(reason.to_string())),
            sanitized,
            KeyAlgorithm::AES256GCM,
        )
        .await
    }
}
