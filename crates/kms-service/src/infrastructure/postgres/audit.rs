use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    domain::audit::{models::AuditLog, repository::AuditRepository},
    errors::{AppError, AppResult},
};

pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    async fn record(&self, log: AuditLog) -> AppResult<()> {
        let prev_hash = sqlx::query_scalar::<_, Option<Vec<u8>>>(
            "SELECT signature FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .flatten()
        .map(hex::encode);

        let payload = serde_json::json!({
            "caller_service": log.caller_service.to_string(),
            "target_service": log.target_service.to_string(),
            "action": format!("{:?}", log.action),
            "algorithm": format!("{:?}", log.algorithm),
            "status": format!("{:?}", log.status),
            "reason": log.reason,
            "prev_hash": prev_hash,
            "timestamp": log.timestamp.to_rfc3339(),
        })
        .to_string();

        let signature = Sha256::digest(payload.as_bytes()).to_vec();

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
                signature: Some(signature),
            },
        )
        .await
        .map_err(AppError::from)?;

        Ok(())
    }
}
