use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use zeroize::Zeroizing;

use super::{GeneratedCredential, TargetResourceProvider};
use crate::errors::AppError;

fn postgres_ddl_error(operation: &str, username: &str, err: impl std::fmt::Display) -> AppError {
    tracing::error!(
        target: "infra::db",
        operation,
        username,
        status = "failed",
        error = %err,
        "PostgreSQL DDL operation failed"
    );
    AppError::Internal(format!(
        "PostgreSQL {} operation failed for user '{}': {}",
        operation, username, err
    ))
}

pub struct PostgresTargetProvider;

#[async_trait]
impl TargetResourceProvider for PostgresTargetProvider {
    async fn create_user(
        &self,
        target_conn_str: &str,
        _caller_service: &str,
        username: &str,
        granted_role: Option<&str>,
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        tracing::debug!(
            target: "infra::db",
            operation = "create_user",
            username,
            ttl_seconds,
            "Starting PostgreSQL user creation"
        );

        let password_bytes = password.ok_or_else(|| {
            tracing::warn!(
                target: "infra::db",
                operation = "create_user",
                username,
                "Missing password for PostgreSQL user creation"
            );
            AppError::Internal("No password provided for Postgres provider".to_string())
        })?;

        let password_text = match std::str::from_utf8(password_bytes) {
            Ok(v) => Zeroizing::new(v.to_owned()),
            Err(_) => Zeroizing::new(BASE64.encode(password_bytes)),
        };

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await
            .map_err(|e| postgres_ddl_error("create_user", username, e))?;

        let safe_username = quote_sql_identifier(username);
        let safe_password = escape_sql_literal(password_text.as_str());
        let expiry = (Utc::now() + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%d %H:%M:%S%.6f%z")
            .to_string();

        let create_sql = format!(
            "CREATE USER {} WITH PASSWORD '{}' VALID UNTIL '{}' INHERIT;",
            safe_username, safe_password, expiry
        );

        sqlx::query(&create_sql)
            .execute(&pool)
            .await
            .map_err(|e| postgres_ddl_error("create_user", username, e))?;

        if let Some(role) = granted_role.filter(|r| !r.trim().is_empty()) {
            let safe_role = quote_sql_identifier(role.trim());
            let grant_sql = format!("GRANT {} TO {};", safe_role, safe_username);
            sqlx::query(&grant_sql)
                .execute(&pool)
                .await
                .map_err(|e| postgres_ddl_error("grant_role", username, e))?;
        }

        tracing::info!(
            target: "infra::db",
            operation = "create_user",
            username = %username,
            ttl_seconds = ttl_seconds,
            status = "success",
            "PostgreSQL DDL executed"
        );

        Ok(GeneratedCredential {
            username: username.to_string(),
            secret: Zeroizing::new(password_text.to_string()),
            ttl_seconds,
        })
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await
            .map_err(|e| postgres_ddl_error("drop_user", username, e))?;

        let quoted_username = quote_sql_identifier(username);
        let drop_sql = format!(
            "REASSIGN OWNED BY {} TO CURRENT_USER; DROP OWNED BY {}; DROP USER IF EXISTS {};",
            quoted_username, quoted_username, quoted_username
        );

        sqlx::query(&drop_sql)
            .execute(&pool)
            .await
            .map_err(|e| postgres_ddl_error("drop_user", username, e))?;

        Ok(())
    }
}

fn quote_sql_identifier(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'' , "''")
}
