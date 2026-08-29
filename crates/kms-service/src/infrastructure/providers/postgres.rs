use async_trait::async_trait;
use rand::Rng;
use rand::distributions::Alphanumeric;
use sqlx::postgres::PgPoolOptions;

use super::{GeneratedCredential, TargetResourceProvider};
use crate::errors::AppError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

pub struct PostgresTargetProvider;

#[async_trait]
impl TargetResourceProvider for PostgresTargetProvider {
    async fn create_user(
        &self,
        target_conn_str: &str,
        role: &str,
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to connect to target PG: {}", e))
            })?;

        let random_suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();

        let username = format!("kms_tmp_{}", random_suffix);

        // Use provided password bytes when available, otherwise generate a random password
        let password: String = if let Some(bytes) = password {
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => BASE64.encode(bytes),
            }
        } else {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect()
        };

        let create_query = format!(
            "CREATE USER {} WITH PASSWORD '{}' VALID UNTIL NOW() + INTERVAL '{} seconds';",
            username, password, ttl_seconds
        );
        let grant_query = format!("GRANT {} TO {};", role, username);

        sqlx::query(&create_query)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create PG target user: {}", e)))?;

        sqlx::query(&grant_query)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to grant PG role: {}", e)))?;

        Ok(GeneratedCredential {
            username,
            secret: password,
            ttl_seconds,
        })
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        let pool = PgPoolOptions::new()
            .connect(target_conn_str)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to connect to target PG: {}", e))
            })?;

        let drop_query = format!("DROP USER IF EXISTS {};", username);
        sqlx::query(&drop_query)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to drop PG user: {}", e)))?;

        Ok(())
    }
}
