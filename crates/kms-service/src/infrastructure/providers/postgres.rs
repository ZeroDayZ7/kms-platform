use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;
use rand::distributions::Alphanumeric;
use sqlx::postgres::PgPoolOptions;

use super::{GeneratedCredential, TargetResourceProvider};
use crate::errors::AppError;

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

        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Postgres provider".to_string())
        })?;
        let password: String = match std::str::from_utf8(password_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => BASE64.encode(password_bytes),
        };

        // 1. ROUND-TRIP: Generowanie połączonego, bezpiecznego ciągu DDL po stronie Postgresa
        let query_builder = r#"
            SELECT format(
                'CREATE USER %s WITH PASSWORD %L VALID UNTIL NOW() + INTERVAL %L seconds; GRANT %s TO %s;',
                quote_ident($1),
                $2,
                $3,
                quote_ident($4),
                quote_ident($1)
            )
        "#;

        let row: (String,) = sqlx::query_as(query_builder)
            .bind(&username)
            .bind(&password)
            .bind(ttl_seconds)
            .bind(role)
            .fetch_one(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to build SQL batch: {}", e)))?;

        let combined_ddl = row.0;

        // 2. ROUND-TRIP: Wykonanie CREATE USER oraz GRANT w jednym batchu
        sqlx::query(&combined_ddl)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to execute combined PG DDL: {}", e)))?;

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

        let drop_row: (String,) =
            sqlx::query_as("SELECT format('DROP USER IF EXISTS %s;', quote_ident($1))")
                .bind(username)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    AppError::Internal(format!("Failed to build DROP USER statement: {}", e))
                })?;

        sqlx::query(&drop_row.0)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to drop PG user: {}", e)))?;

        Ok(())
    }
}
