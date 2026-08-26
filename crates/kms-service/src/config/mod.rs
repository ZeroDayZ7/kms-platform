// src/config/mod.rs
use config::{Config, ConfigError, Environment, File};

mod database;
mod log;
mod redis;
mod server;
mod settings;

pub mod acl;
pub mod cors;
pub mod crypto;
pub mod rate_limit;

pub use cors::HttpMethod;
pub use database::DatabaseConfig;
pub use log::LogConfig;
pub use log::LogFormat;
pub use log::LogLevel;
pub use redis::RedisConfig;
pub use settings::Settings;

//#region load
pub fn load() -> Result<Settings, ConfigError> {
    let base_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("settings.toml");

    load_from(base_path)
}

// src/config/mod.rs

pub fn load_from<P: AsRef<std::path::Path>>(path: P) -> Result<Settings, ConfigError> {
    let root_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let env_path = root_dir.join(".env");

    dotenvy::from_filename(&env_path).ok();

    let settings_path = path.as_ref();
    let config_dir = settings_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("config"));
    let acl_path = config_dir.join("services_acl.toml");

    let settings: Settings = Config::builder()
        .add_source(File::from(settings_path).required(true))
        .add_source(File::from(acl_path).required(true))
        .add_source(
            Environment::default()
                .separator("__")
                .try_parsing(true)
                .with_list_parse_key("value"),
        )
        .build()?
        .try_deserialize()?;

    Ok(settings)
}
