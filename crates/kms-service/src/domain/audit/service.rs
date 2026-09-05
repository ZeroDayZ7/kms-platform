use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
        },
        keys::models::{KeyAlgorithm, ServiceId},
    },
    errors::AppResult,
};

#[derive(Debug, Clone)]
pub struct AuditRecordInput {
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
    pub timestamp: Option<chrono::DateTime<Utc>>,
    pub id: Option<Uuid>,
}

impl AuditRecordInput {
    pub fn new(
        caller_service: ServiceId,
        target_service: ServiceId,
        action: AuditAction,
        algorithm: KeyAlgorithm,
        status: AuditStatus,
    ) -> Self {
        Self {
            caller_service,
            target_service,
            action,
            algorithm,
            status,
            reason: None,
            request_id: None,
            operation_id: None,
            target_id: None,
            metadata: None,
            timestamp: None,
            id: None,
        }
    }
}

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

    pub async fn record_event(&self, input: AuditRecordInput) -> AppResult<()> {
        let audit_log = AuditLog {
            id: input.id.unwrap_or_else(Uuid::now_v7),
            caller_service: input.caller_service,
            target_service: input.target_service,
            action: input.action,
            algorithm: input.algorithm,
            status: input.status,
            reason: input
                .reason
                .as_deref()
                .and_then(|reason| AuditLog::sanitize_reason(Some(reason))),
            request_id: input.request_id,
            operation_id: input.operation_id,
            target_id: input.target_id,
            metadata: input.metadata,
            timestamp: input.timestamp.unwrap_or_else(Utc::now),
        };

        self.repo.record(audit_log).await
    }

    pub async fn record_success(
        &self,
        caller_service: ServiceId,
        target_service: ServiceId,
        action: AuditAction,
        algorithm: KeyAlgorithm,
        reason: Option<&str>,
    ) -> AppResult<()> {
        self.record_event(AuditRecordInput {
            caller_service,
            target_service,
            action,
            algorithm,
            status: AuditStatus::Success,
            reason: reason.map(str::to_owned),
            request_id: None,
            operation_id: None,
            target_id: None,
            metadata: None,
            timestamp: None,
            id: None,
        })
        .await
    }

    pub async fn record_access_denied(
        &self,
        caller_service: ServiceId,
        target_service: ServiceId,
        action: AuditAction,
        algorithm: KeyAlgorithm,
        reason: &str,
    ) -> AppResult<()> {
        self.record_event(AuditRecordInput {
            caller_service,
            target_service,
            action,
            algorithm,
            status: AuditStatus::AccessDenied,
            reason: Some(reason.to_owned()),
            request_id: None,
            operation_id: None,
            target_id: None,
            metadata: None,
            timestamp: None,
            id: None,
        })
        .await
    }
}
