use kms_db::PgPool;

pub struct PostgresClient {
    pub pool: PgPool,
}

impl PostgresClient {
    //#region new
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    //#region pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}