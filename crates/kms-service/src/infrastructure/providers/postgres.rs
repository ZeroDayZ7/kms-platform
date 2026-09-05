use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;
use rand::distributions::Alphanumeric;
use sqlx::postgres::PgPoolOptions;
use zeroize::Zeroize;

use super::{GeneratedCredential, TargetResourceProvider};
use crate::errors::AppError;

fn postgres_ddl_error(operation: &str, username: &str) -> AppError {
    tracing::error!(
        target: "infra::db",
        operation,
        username,
        status = "failed",
        "PostgreSQL DDL operation failed"
    );
    AppError::Internal(format!("PostgreSQL {} operation failed", operation))
}

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

        let mut password_str: String = match std::str::from_utf8(password_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => BASE64.encode(password_bytes),
        };

        // 1. Wygenerowanie i wyliczenie DDL z uwzględnieniem klauzuli INHERIT
        let create_user_builder = r#"
            SELECT format(
                'CREATE USER %I WITH PASSWORD %L VALID UNTIL %L INHERIT;',
                $1,
                $2,
                to_char(NOW() + ($3 * INTERVAL '1 second'), 'YYYY-MM-DD HH24:MI:SS.USOF')
            )
        "#;

        let create_row: (String,) = sqlx::query_as(create_user_builder)
            .bind(&username)
            .bind(&password_str)
            .bind(ttl_seconds)
            .fetch_one(&pool)
            .await
            .map_err(|_| postgres_ddl_error("create_user", &username))?;

        let create_user_ddl = create_row.0;
        tracing::info!(
            operation = "create_user",
            username = %username,
            target = "postgres",
            "Executing PostgreSQL DDL"
        );

        // Wykonanie CREATE USER
        if sqlx::query(&create_user_ddl).execute(&pool).await.is_err() {
            password_str.zeroize();
            return Err(postgres_ddl_error("create_user", &username));
        }

        // 2. Nadanie roli (GRANT), o ile jest podana
        if !role.is_empty() {
            let grant_builder = r#"
                SELECT format(
                    'GRANT %I TO %I;',
                    $1,
                    $2
                )
            "#;

            let grant_row: (String,) = sqlx::query_as(grant_builder)
                .bind(role)
                .bind(&username)
                .fetch_one(&pool)
                .await
                .map_err(|_| {
                    password_str.zeroize();
                    postgres_ddl_error("grant_role", &username)
                })?;

            let grant_ddl = grant_row.0;
            tracing::info!(
                operation = "grant_role",
                username = %username,
                target = "postgres",
                "Executing PostgreSQL DDL"
            );

            if sqlx::query(&grant_ddl).execute(&pool).await.is_err() {
                password_str.zeroize();
                return Err(postgres_ddl_error("grant_role", &username));
            }
        } else {
            tracing::warn!(
                operation = "grant_role",
                username = %username,
                target = "postgres",
                "Role parameter is empty; skipping GRANT"
            );
        }

        Ok(GeneratedCredential {
            username,
            secret: password_str,
            ttl_seconds,
        })
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to connect to target PG: {}", e))
            })?;

        let drop_sql_builder = r#"
            SELECT format(
                'REASSIGN OWNED BY %1$s TO CURRENT_USER; DROP OWNED BY %1$s; DROP USER IF EXISTS %1$s;',
                quote_ident($1)
            )
        "#;

        let drop_row: (String,) = sqlx::query_as(drop_sql_builder)
            .bind(username)
            .fetch_one(&pool)
            .await
            .map_err(|_| postgres_ddl_error("drop_user", username))?;

        let drop_sql = drop_row.0;
        tracing::info!(
            operation = "drop_user",
            username = %username,
            target = "postgres",
            "Executing PostgreSQL DDL"
        );

        sqlx::query(&drop_sql)
            .execute(&pool)
            .await
            .map_err(|_| postgres_ddl_error("drop_user", username))?;

        Ok(())
    }
}
