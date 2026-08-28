use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default)]
    pub auth_source: Option<String>,
}

fn default_port() -> u16 {
    5432
}

fn default_pool_size() -> u32 {
    10
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 5432,
            user: None,
            password: None,
            name: "kms_db".to_owned(),
            pool_size: 10,
            auth_source: None,
        }
    }
}

impl DatabaseConfig {
    pub fn password_value(&self) -> Option<String> {
        if let Some(password) = self
            .password
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            return Some(password.to_owned());
        }

        let password_file = std::env::var("DATABASE__PASSWORD_FILE")
            .or_else(|_| std::env::var("DATABASE_PASSWORD_FILE"))
            .ok();

        let raw = password_file.and_then(|path| std::fs::read_to_string(path).ok())?;
        let password = raw.trim();
        (!password.is_empty()).then(|| password.to_owned())
    }

    pub fn connection_string(&self) -> String {
        let password = self.password_value();
        let credentials = match (self.user.as_deref(), password.as_deref()) {
            (Some(user), Some(pass)) if !user.is_empty() && !pass.is_empty() => {
                format!("{}:{}@", user, pass)
            }
            (Some(user), _) if !user.is_empty() => format!("{}@", user),
            _ => String::new(),
        };

        format!(
            "postgresql://{credentials}{host}:{port}/{database}",
            credentials = credentials,
            host = self.host,
            port = self.port,
            database = self.name,
        )
    }
}

pub async fn connect(db_set: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(db_set.pool_size)
        .connect(&db_set.connection_string())
        .await?;

    sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await
        .map_err(|error| {
            tracing::error!(?error, "Unable to reach PostgreSQL database");
            error
        })?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::DatabaseConfig;

    #[test]
    fn connection_string_uses_credentials_when_present() {
        let cfg = DatabaseConfig {
            host: "localhost".to_owned(),
            port: 5432,
            user: Some("kms_app_user".to_owned()),
            password: Some("secret".to_owned()),
            name: "kms_db".to_owned(),
            pool_size: 10,
            auth_source: None,
        };

        assert_eq!(
            cfg.connection_string(),
            "postgresql://kms_app_user:secret@localhost:5432/kms_db"
        );
    }

    #[test]
    fn connection_string_without_password_omits_credentials() {
        let cfg = DatabaseConfig {
            host: "localhost".to_owned(),
            port: 5432,
            user: Some("kms_app_user".to_owned()),
            password: None,
            name: "kms_db".to_owned(),
            pool_size: 10,
            auth_source: None,
        };

        assert_eq!(
            cfg.connection_string(),
            "postgresql://kms_app_user@localhost:5432/kms_db"
        );
    }
}
