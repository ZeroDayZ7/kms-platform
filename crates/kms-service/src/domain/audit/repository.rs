// src/domain/audit/repository.rs
use crate::{domain::audit::models::AuditLog, errors::AppResult};
use async_trait::async_trait;

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn record(&self, log: AuditLog) -> AppResult<()>;
}
