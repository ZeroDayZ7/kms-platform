// src/infrastructure/mongodb/audit.rs
use async_trait::async_trait;
use mongodb::{Collection, Database};
use std::sync::Arc;

use crate::{
    domain::audit::{models::AuditLog, repository::AuditRepository},
    errors::AppResult,
};

pub struct MongoAuditRepository {
    collection: Collection<AuditLog>,
}

impl MongoAuditRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("audit_logs"),
        }
    }

    pub fn from_arc(db: Arc<Database>) -> Self {
        Self::new(&db)
    }
}

#[async_trait]
impl AuditRepository for MongoAuditRepository {
    async fn record(&self, log: AuditLog) -> AppResult<()> {
        self.collection.insert_one(log).await?;
        Ok(())
    }
}
