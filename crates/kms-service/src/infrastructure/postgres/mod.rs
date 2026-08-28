pub mod audit;
pub mod keys;

pub use audit::PgAuditRepository;
pub use keys::PgKeyRepository;

use crate::errors::{AppError, AppResult};
use kms_db::connect;
use sqlx::PgPool;

pub async fn init_postgres(db_set: &crate::config::DatabaseConfig) -> AppResult<PgPool> {
    connect(db_set)
        .await
        .map_err(|err| AppError::ConfigError(format!("Błędne połączenie z PostgreSQL: {}", err)))
}
