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

        // Canonical serialization: deterministic field order
        let mut map = serde_json::Map::new();
        map.insert(
            "id".to_string(),
            serde_json::Value::String(log.id.to_string()),
        );
        map.insert(
            "caller_service".to_string(),
            serde_json::Value::String(log.caller_service.to_string()),
        );
        map.insert(
            "target_service".to_string(),
            serde_json::Value::String(log.target_service.to_string()),
        );
        map.insert(
            "action".to_string(),
            serde_json::Value::String(format!("{:?}", log.action)),
        );
        map.insert(
            "algorithm".to_string(),
            serde_json::Value::String(format!("{:?}", log.algorithm)),
        );
        map.insert(
            "status".to_string(),
            serde_json::Value::String(format!("{:?}", log.status)),
        );
        map.insert(
            "reason".to_string(),
            match &log.reason {
                Some(r) => serde_json::Value::String(r.clone()),
                None => serde_json::Value::Null,
            },
        );
        map.insert(
            "prev_hash".to_string(),
            serde_json::Value::String(prev_hash.clone()),
        );
        map.insert(
            "timestamp".to_string(),
            serde_json::Value::String(log.timestamp.to_rfc3339()),
        );

        let payload = serde_json::Value::Object(map).to_string();

        // Compute SHA-256 hex of the canonical payload
        let hash_bytes = Sha256::digest(payload.as_bytes()).to_vec();
        let hash_hex = hex::encode(hash_bytes.clone());

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
