use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;
use rand::distributions::Alphanumeric;
use sqlx::postgres::PgPoolOptions;
use zeroize::Zeroize;

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
            .map_err(|e| {
                AppError::Internal(format!("Failed to build CREATE USER DDL statement: {}", e))
            })?;

        let create_user_ddl = create_row.0;

        println!(
            "[DEBUG-DDL] Wygenerowany CREATE USER SQL: {}",
            create_user_ddl
        );
        tracing::info!(sql = %create_user_ddl, "Wykonuję DDL tworzenia użytkownika PG");

        // Wykonanie CREATE USER
        if let Err(err) = sqlx::query(&create_user_ddl).execute(&pool).await {
            password_str.zeroize();
            return Err(AppError::Internal(format!(
                "Failed to execute CREATE USER PG DDL (SQL: [{}]): {}",
                create_user_ddl, err
            )));
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
                .map_err(|e| {
                    password_str.zeroize();
                    AppError::Internal(format!("Failed to build GRANT DDL statement: {}", e))
                })?;

            let grant_ddl = grant_row.0;

            println!("[DEBUG-DDL] Wygenerowany GRANT SQL: {}", grant_ddl);
            tracing::info!(sql = %grant_ddl, "Wykonuję DDL nadawania uprawnień PG");

            if let Err(err) = sqlx::query(&grant_ddl).execute(&pool).await {
                password_str.zeroize();
                return Err(AppError::Internal(format!(
                    "Failed to execute GRANT PG DDL (SQL: [{}]): {}",
                    grant_ddl, err
                )));
            }
        } else {
            tracing::warn!("Parametr 'role' jest pusty - pomijam krok GRANT!");
            println!("[WARN] Parametr 'role' jest pusty - pominięto GRANT!");
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
            .map_err(|e| {
                AppError::Internal(format!("Failed to build DROP USER statement: {}", e))
            })?;

        let drop_sql = drop_row.0;
        println!("[DEBUG-DDL] Wygenerowany REVOKE/DROP SQL: {}", drop_sql);

        sqlx::query(&drop_sql)
            .execute(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to drop PG user: {}", e)))?;

        Ok(())
    }
}