use async_trait::async_trait;
use kms_db::target_providers::PostgresDdlExecutor;

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
        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Postgres provider".to_string())
        })?;

        let created =
            PostgresDdlExecutor::create_user(target_conn_str, role, ttl_seconds, password_bytes)
                .await
                .map_err(|_| postgres_ddl_error("create_user", "target-user"))?;

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
            .map_err(|_| postgres_ddl_error("drop_user", username))?;

        Ok(())
    }
}
