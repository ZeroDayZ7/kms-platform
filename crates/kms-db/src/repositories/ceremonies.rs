use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction, PgPool};
use uuid::Uuid;

pub struct CeremonyQueries;

impl CeremonyQueries {
    pub async fn insert_tx(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        kind: &str,
        payload: &[u8],
        status: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO ceremonies (id, kind, payload, status, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(id)
            .bind(kind)
            .bind(payload)
            .bind(status)
            .bind(created_at)
            .execute(&mut **tx)
            .await
            .map(|_| ())
    }
}

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
