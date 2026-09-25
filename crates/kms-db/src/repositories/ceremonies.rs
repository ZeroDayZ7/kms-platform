use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug)]
pub struct CeremonyRecord {
    pub id: Uuid,
    pub kind: String,
    pub payload: Vec<u8>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub struct PgCeremonyRepository {
    pub pool: PgPool,
}

impl PgCeremonyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_ceremony(&self, kind: &str, payload: &[u8]) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let created_at: DateTime<Utc> = Utc::now();
        sqlx::query(
            "INSERT INTO ceremonies (id, kind, payload, status, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(kind)
        .bind(payload)
        .bind("RECORDED")
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }
}
