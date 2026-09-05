use async_trait::async_trait;
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use kms_db::{PgPool, repositories::{AuditInsert, AuditQueries}};

use crate::{
    domain::audit::{models::AuditLog, repository::AuditRepository},
    errors::{AppError, AppResult},
};

pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    //#region new
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    async fn record(&self, log: AuditLog) -> AppResult<()> {
        let prev_hash_opt = AuditQueries::latest_hash(&self.pool)
            .await
            .map_err(|err| AppError::DatabaseError(format!("Database operation failed: {err}")))?;

        let prev_hash = prev_hash_opt.unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        let action_str = format!("{:?}", log.action);
        let algorithm_str = format!("{:?}", log.algorithm);
        let status_str = format!("{:?}", log.status);

        let safe_reason = AuditLog::sanitize_reason(log.reason.as_deref());
        let hash_hex = compute_audit_hash(&AuditHashInput {
            id: &log.id.to_string(),
            caller_service: &log.caller_service.0,
            target_service: &log.target_service.0,
            action: &action_str,
            algorithm: &algorithm_str,
            status: &status_str,
            reason: safe_reason.as_deref(),
            prev_hash: &prev_hash,
            timestamp: &log.timestamp,
            request_id: log.request_id.as_deref(),
            operation_id: log.operation_id.as_deref(),
            target_id: log.target_id.as_deref(),
            metadata: log.metadata.as_deref(),
        });

        AuditQueries::insert(
            &self.pool,
            AuditInsert {
                id: log.id,
                caller_service: log.caller_service.0,
                target_service: log.target_service.0,
                action: action_str,
                algorithm: algorithm_str,
                status: status_str,
                reason: safe_reason,
                prev_hash,
                hash: hash_hex,
                signature: None,
                request_id: log.request_id,
                operation_id: log.operation_id,
                target_id: log.target_id,
                metadata: log.metadata,
                created_at: log.timestamp,
            },
        )
        .await
        .map_err(|err| AppError::DatabaseError(format!("Database operation failed: {err}")))?;

        Ok(())
    }
}
