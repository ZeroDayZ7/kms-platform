use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use rand::Rng;
use rand::distributions::Alphanumeric;
use sqlx::postgres::PgPoolOptions;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct ProvisionedUser {
    pub username: String,
    pub secret: Zeroizing<String>,
    pub ttl_seconds: i64,
}

pub struct PostgresDdlExecutor;

impl PostgresDdlExecutor {
    pub async fn create_user(
        target_conn_str: &str,
        role: &str,
        ttl_seconds: i64,
        password: &[u8],
    ) -> Result<ProvisionedUser, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await?;

        let username = format!(
            "kms_tmp_{}",
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(12)
                .map(char::from)
                .collect::<String>()
        );

        let password_bytes = Zeroizing::new(password.to_vec());
        let password_text = match std::str::from_utf8(password_bytes.as_ref()) {
            Ok(value) => Zeroizing::new(value.to_owned()),
            Err(_) => Zeroizing::new(BASE64.encode(password_bytes.as_ref() as &[u8])),
        };

        let safe_password = escape_sql_literal(password_text.as_str());
        let safe_username = quote_sql_identifier(&username);
        let safe_role = if role.trim().is_empty() {
            None
        } else {
            Some(quote_sql_identifier(role.trim()))
        };

        let expiry = (Utc::now() + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%d %H:%M:%S%.6f%z")
            .to_string();
        let create_sql = format!(
            "CREATE USER {} WITH PASSWORD '{}' VALID UNTIL '{}' INHERIT;",
            safe_username, safe_password, expiry
        );

        sqlx::query(&create_sql).execute(&pool).await?;

        if let Some(safe_role_sql) = safe_role {
            let grant_sql = format!("GRANT {} TO {};", safe_role_sql, safe_username);
            sqlx::query(&grant_sql).execute(&pool).await?;
        }

        Ok(ProvisionedUser {
            username,
            secret: Zeroizing::new(password_text.to_string()),
            ttl_seconds,
        })
    }

    pub async fn revoke_user(target_conn_str: &str, username: &str) -> Result<(), sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(target_conn_str)
            .await?;

        let quoted_username = quote_sql_identifier(username);
        let drop_sql = format!(
            "REASSIGN OWNED BY {} TO CURRENT_USER; DROP OWNED BY {}; DROP USER IF EXISTS {};",
            quoted_username, quoted_username, quoted_username
        );

        sqlx::query(&drop_sql).execute(&pool).await?;
        Ok(())
    }
}

fn quote_sql_identifier(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}
