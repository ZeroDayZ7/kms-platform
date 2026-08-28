use async_trait::async_trait;
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use sqlx::PgPool;

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
        // Fetch last hash (prev_hash) from latest record
        let prev_hash_opt = sqlx::query_scalar::<_, String>(
            "SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        let prev_hash = prev_hash_opt.unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        let hash_hex = compute_audit_hash(&AuditHashInput {
            id: &log.id.to_string(),
            caller_service: &log.caller_service.0,
            target_service: &log.target_service.0,
            action: &format!("{:?}", log.action),
            algorithm: &format!("{:?}", log.algorithm),
            status: &format!("{:?}", log.status),
            reason: log.reason.as_deref(),
            prev_hash: &prev_hash,
            timestamp: &log.timestamp,
        });

        // Optionally sign the hash with vHSM here. For now we leave signature NULL (to be filled by vHSM flow).
        let signature: Option<Vec<u8>> = None;

        crate::infrastructure::sqlc::queries::insert_audit_log(
            &self.pool,
            crate::infrastructure::sqlc::queries::InsertAuditLogParams {
                id: log.id,
                caller_service: log.caller_service.0,
                target_service: log.target_service.0,
                action: format!("{:?}", log.action),
                algorithm: format!("{:?}", log.algorithm),
                status: format!("{:?}", log.status),
                reason: log.reason,
                prev_hash,
                hash: hash_hex,
                signature,
            },
        )
        .await
        .map_err(AppError::from)?;

        Ok(())
    }
}
