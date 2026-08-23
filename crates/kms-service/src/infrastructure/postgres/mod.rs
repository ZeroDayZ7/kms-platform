pub mod audit;
pub mod keys;

pub use audit::PgAuditRepository;
pub use keys::PgKeyRepository;

use crate::errors::{AppError, AppResult};
use sqlx::PgPool;

pub async fn init_postgres(db_set: &crate::config::DatabaseConfig) -> AppResult<PgPool> {
    let credentials = match (db_set.user.as_deref(), db_set.password.as_deref()) {
        (Some(user), Some(pass)) if !user.is_empty() && !pass.is_empty() => {
            format!("{}:{}@", user, pass)
        }
        _ => String::new(),
    };

    let conn_str = format!(
        "postgresql://{credentials}{host}:{port}/{database}",
        credentials = credentials,
        host = db_set.host,
        port = db_set.port,
        database = db_set.name,
    );

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(db_set.pool_size)
        .connect(&conn_str)
        .await
        .map_err(|err| AppError::ConfigError(format!("Błędny URI PostgreSQL: {}", err)))?;

    sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await
        .map_err(|err| AppError::ConfigError(format!("Błąd połączenia z PostgreSQL: {}", err)))?;

    sqlx::migrate!("./sqlc/migrations")
        .run(&pool)
        .await
        .map_err(|err| AppError::ConfigError(format!("Błąd wykonywania migracji: {}", err)))?;

    tracing::info!("✅ Connected to PostgreSQL & migrations applied");
    Ok(pool)
}
