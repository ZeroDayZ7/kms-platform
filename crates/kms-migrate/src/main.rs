// crates/kms-migrate/src/main.rs
use std::path::Path;

use anyhow::Context;
use config::{Config, Environment, File};
use kms_db::{DatabaseConfig, connect};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
struct Settings {
    #[serde(default)]
    database: DatabaseConfig,
}

fn load_settings() -> anyhow::Result<Settings> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let candidate_paths = [
        manifest_dir.join("config").join("settings.toml"),
        Path::new("config/settings.toml").to_path_buf(),
    ];

    let mut builder = Config::builder().add_source(
        Environment::default()
            .separator("__")
            .try_parsing(true)
            .with_list_parse_key("value"),
    );

    for candidate in candidate_paths {
        if candidate.exists() {
            builder = builder.add_source(File::from(candidate).required(false));
        }
    }

    let settings: Settings = builder.build()?.try_deserialize()?;
    Ok(settings)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inicjalizacja formatowania logów w konsoli
    tracing_subscriber::fmt::init();

    // Ładowanie zmiennych z lokalnego .env (jeśli istnieje)
    dotenvy::dotenv().ok();

    tracing::info!("🚀 Starting KMS database migrations...");

    // 1. Wczytanie konfiguracji i pobranie poświadczeń bazy (np. roota z ENV)
    let settings = load_settings().context("Failed to load migration configuration")?;

    // 2. Połączenie z bazą przy użyciu czystego kms-db
    let pool = connect(&settings.database)
        .await
        .context("Failed to connect to PostgreSQL for migrations")?;

    tracing::info!("⏳ Applying migrations from local ./migrations directory...");

    // 3. Wykonanie migracji z folderu wewnątrz kms-migrate
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("Failed to execute database migrations")?;

    tracing::info!("✅ Migration runner completed successfully");
    Ok(())
}
