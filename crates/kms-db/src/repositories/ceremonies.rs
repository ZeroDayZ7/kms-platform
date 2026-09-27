use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub struct CeremonyQueries;

impl CeremonyQueries {
    /// No-op placeholder. Ceremony recording is performed by the service layer via audit logs.
    /// This intentionally does not perform any SQL against a `ceremonies` table.
    pub async fn insert_tx(
        _tx: &mut Transaction<'_, Postgres>,
        _id: Uuid,
        _kind: &str,
        _payload: &[u8],
        _status: &str,
        _created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
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

    pub async fn insert_ceremony(&self, _kind: &str, _payload: &[u8]) -> Result<Uuid, sqlx::Error> {
        // Intentionally return a generated id but do not insert into DB.
        Ok(Uuid::new_v4())
    }
}
