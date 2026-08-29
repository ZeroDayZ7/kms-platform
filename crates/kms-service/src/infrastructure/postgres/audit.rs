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

        let action_str = format!("{:?}", log.action);
        let algorithm_str = format!("{:?}", log.algorithm);
        let status_str = format!("{:?}", log.status);

        let hash_hex = compute_audit_hash(&AuditHashInput {
            id: &log.id.to_string(),
            caller_service: &log.caller_service.0,
            target_service: &log.target_service.0,
            action: &action_str,
            algorithm: &algorithm_str,
            status: &status_str,
            reason: log.reason.as_deref(),
            prev_hash: &prev_hash,
            timestamp: &log.timestamp,
        });

        // Optionally sign the hash with vHSM here. For now we leave signature NULL (to be filled by vHSM flow).
        let signature: Option<Vec<u8>> = None;

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, caller_service, target_service, action, algorithm, 
                status, reason, prev_hash, hash, signature, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )
            "#,
        )
        .bind(log.id)
        .bind(log.caller_service.0)
        .bind(log.target_service.0)
        .bind(action_str)
        .bind(algorithm_str)
        .bind(status_str)
        .bind(log.reason)
        .bind(prev_hash)
        .bind(hash_hex)
        .bind(signature)
        .bind(log.timestamp)
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(())
    }
}
