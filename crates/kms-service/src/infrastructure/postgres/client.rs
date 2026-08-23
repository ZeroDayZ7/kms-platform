use sqlx::PgPool;

pub struct PostgresClient {
    pub pool: PgPool,
}

impl PostgresClient {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}