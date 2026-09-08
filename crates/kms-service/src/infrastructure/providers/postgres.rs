use async_trait::async_trait;
use kms_db::target_providers::PostgresDdlExecutor;

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
        role: &str,
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Postgres provider".to_string())
        })?;

        // Zmienna `role` zawiera wygenerowaną nazwę użytkownika (np. kms_authserv_a1b2c3d4)
        let created =
            PostgresDdlExecutor::create_user(target_conn_str, role, ttl_seconds, password_bytes)
                .await
                .map_err(|err| postgres_ddl_error("create_user", role, err))?;

        tracing::info!(
            operation = "create_user",
            username = %created.username,
            target = "postgres",
            ttl_seconds = created.ttl_seconds,
            "PostgreSQL DDL executed via kms-db adapter"
        );

        Ok(GeneratedCredential {
            username: created.username,
            secret: created.secret,
            ttl_seconds: created.ttl_seconds,
        })
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        tracing::info!(
            operation = "drop_user",
            username = %username,
            target = "postgres",
            "Preparing PostgreSQL user cleanup via kms-db adapter"
        );

        PostgresDdlExecutor::revoke_user(target_conn_str, username)
            .await
            .map_err(|err| postgres_ddl_error("drop_user", username, err))?;

        Ok(())
    }
}
