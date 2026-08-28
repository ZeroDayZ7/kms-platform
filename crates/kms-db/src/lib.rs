// crates/kms-db/src/lib.rs
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::error::Error;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseConfigError {
    InvalidPort { value: String },
    InvalidPoolSize { value: String },
}

impl fmt::Display for DatabaseConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort { value } => {
                write!(
                    f,
                    "Invalid PostgreSQL port value: {value:?}. Expected a valid u16."
                )
            }
            Self::InvalidPoolSize { value } => {
                write!(
                    f,
                    "Invalid PostgreSQL pool size value: {value:?}. Expected a valid u32."
                )
            }
        }
    }
}

impl Error for DatabaseConfigError {}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default)]
    pub auth_source: Option<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_owned()
}

fn default_port() -> u16 {
    5432
}

fn default_name() -> String {
    "kms_db".to_owned()
}

fn default_pool_size() -> u32 {
    10
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            user: None,
            password: None,
            name: default_name(),
            pool_size: default_pool_size(),
            auth_source: None,
        }
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, DatabaseConfigError> {
        let host = read_env_var(&["DATABASE__HOST", "DATABASE_HOST"]).unwrap_or_else(default_host);
        let port = match read_env_var(&["DATABASE__PORT", "DATABASE_PORT"]) {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| DatabaseConfigError::InvalidPort { value })?,
            None => default_port(),
        };
        let user = read_env_var(&["DATABASE__USER", "DATABASE_USER"]);
        let password =
            read_env_var(&["DATABASE__PASSWORD", "DATABASE_PASSWORD"]).map(Zeroizing::new);
        let name = read_env_var(&["DATABASE__NAME", "DATABASE_NAME"])
            .or_else(|| std::env::var("POSTGRES_DB").ok())
            .unwrap_or_else(default_name);
        let pool_size = match read_env_var(&["DATABASE__POOL_SIZE", "DATABASE_POOL_SIZE"]) {
            Some(value) => value
                .parse::<u32>()
                .map_err(|_| DatabaseConfigError::InvalidPoolSize { value })?,
            None => default_pool_size(),
        };

        Ok(Self {
            host,
            port,
            user,
            password,
            name,
            pool_size,
            auth_source: None,
        })
    }

    pub fn password_value(&self) -> Option<Zeroizing<String>> {
        if let Some(password) = self
            .password
            .as_ref()
            .filter(|pass| !pass.trim().is_empty())
        {
            return Some(password.clone());
        }

        let password_file = std::env::var("DATABASE__PASSWORD_FILE")
            .or_else(|_| std::env::var("DATABASE_PASSWORD_FILE"))
            .ok()?;

        let raw = Zeroizing::new(std::fs::read_to_string(password_file).ok()?);
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            None
        } else {
            Some(Zeroizing::new(trimmed.to_owned()))
        }
    }

    pub fn connection_string(&self) -> Zeroizing<String> {
        let password = self.password_value();
        let credentials = match (self.user.as_deref(), password.as_deref()) {
            (Some(user), Some(pass)) if !user.is_empty() && !pass.is_empty() => {
                format!("{}:{}@", user, pass)
            }
            (Some(user), _) if !user.is_empty() => format!("{}@", user),
            _ => String::new(),
        };

        Zeroizing::new(format!(
            "postgresql://{credentials}{host}:{port}/{database}",
            credentials = credentials,
            host = self.host,
            port = self.port,
            database = self.name,
        ))
    }
}

fn read_env_var(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| std::env::var(key).ok())
}

pub async fn connect(db_set: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    let conn_str = db_set.connection_string();

    let pool = PgPoolOptions::new()
        .max_connections(db_set.pool_size)
        .connect(&conn_str)
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
    use zeroize::Zeroizing;

    use std::fs;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    unsafe fn set_env_var(key: &str, value: &str) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    unsafe fn remove_env_var(key: &str) {
        unsafe {
            std::env::remove_var(key);
        }
    }

    fn clear_database_env() {
        for key in [
            "DATABASE__HOST",
            "DATABASE_HOST",
            "DATABASE__PORT",
            "DATABASE_PORT",
            "DATABASE__USER",
            "DATABASE_USER",
            "DATABASE__PASSWORD",
            "DATABASE_PASSWORD",
            "DATABASE__PASSWORD_FILE",
            "DATABASE_PASSWORD_FILE",
            "DATABASE__NAME",
            "DATABASE_NAME",
            "POSTGRES_DB",
            "DATABASE__POOL_SIZE",
            "DATABASE_POOL_SIZE",
        ] {
            unsafe {
                remove_env_var(key);
            }
        }
    }

    #[test]
    fn from_env_uses_defaults_when_unset() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();

        let cfg = super::DatabaseConfig::from_env().unwrap();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 5432);
        assert_eq!(cfg.name, "kms_db");
        assert_eq!(cfg.pool_size, super::default_pool_size());
    }

    #[test]
    fn from_env_prefers_double_underscore_over_single_underscore() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();
        unsafe {
            set_env_var("DATABASE__HOST", "primary");
            set_env_var("DATABASE_HOST", "secondary");
        }

        let cfg = super::DatabaseConfig::from_env().unwrap();
        assert_eq!(cfg.host, "primary");
    }

    #[test]
    fn from_env_falls_back_to_single_underscore() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();
        unsafe {
            set_env_var("DATABASE_HOST", "postgres");
        }

        let cfg = super::DatabaseConfig::from_env().unwrap();
        assert_eq!(cfg.host, "postgres");
    }

    #[test]
    fn from_env_uses_postgres_db_when_name_not_set() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();
        unsafe {
            set_env_var("POSTGRES_DB", "test_db");
        }

        let cfg = super::DatabaseConfig::from_env().unwrap();
        assert_eq!(cfg.name, "test_db");
    }

    #[test]
    fn from_env_rejects_invalid_port() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();
        unsafe {
            set_env_var("DATABASE_PORT", "not-a-number");
        }

        let err = super::DatabaseConfig::from_env().unwrap_err();
        assert!(matches!(
            err,
            super::DatabaseConfigError::InvalidPort { .. }
        ));
    }

    #[test]
    fn password_file_is_trimmed_without_newline() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();

        let path = std::env::temp_dir().join(format!(
            "kms-db-password-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "secret\n").unwrap();
        unsafe {
            set_env_var("DATABASE_PASSWORD_FILE", path.to_str().unwrap());
        }

        let cfg = super::DatabaseConfig::default();
        assert_eq!(&*cfg.password_value().unwrap(), "secret");

        unsafe {
            remove_env_var("DATABASE_PASSWORD_FILE");
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_password_has_priority_over_password_file() {
        let _guard = env_lock().lock().unwrap();
        clear_database_env();

        let path = std::env::temp_dir().join(format!(
            "kms-db-password-priority-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "file-secret\n").unwrap();
        unsafe {
            set_env_var("DATABASE_PASSWORD_FILE", path.to_str().unwrap());
            set_env_var("DATABASE_PASSWORD", "env-secret");
        }

        let cfg = super::DatabaseConfig {
            password: Some(Zeroizing::new("env-secret".to_owned())),
            ..super::DatabaseConfig::default()
        };

        assert_eq!(&*cfg.password_value().unwrap(), "env-secret");

        unsafe {
            remove_env_var("DATABASE_PASSWORD_FILE");
            remove_env_var("DATABASE_PASSWORD");
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn connection_string_uses_credentials_when_present() {
        let cfg = DatabaseConfig {
            host: "localhost".to_owned(),
            port: 5432,
            user: Some("kms_app_user".to_owned()),
            password: Some(Zeroizing::new("secret".to_owned())),
            name: "kms_db".to_owned(),
            pool_size: 10,
            auth_source: None,
        };

        assert_eq!(
            *cfg.connection_string(),
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
            *cfg.connection_string(),
            "postgresql://kms_app_user@localhost:5432/kms_db"
        );
    }
}
