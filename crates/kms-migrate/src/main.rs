use anyhow::{Context, anyhow, bail};
use clap::{Parser, Subcommand};
use kms_db::DatabaseConfig;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::time::sleep;
use tracing::{error, info, warn};

const MIGRATION_LOCK_KEY: i64 = 0x4B4D535F4D494752_i64;
const DB_READY_RETRIES: usize = 10;
const DB_READY_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(
    name = "kms-migrate",
    version,
    about = "Production PostgreSQL migration runner for KMS",
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Apply all pending migrations.
    Run {
        #[arg(
            short = 'd',
            long = "dry-run",
            help = "Only list pending migrations without applying them"
        )]
        dry_run: bool,
    },
    /// Show applied and pending migrations.
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalMigration {
    version: i64,
    description: String,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedMigration {
    version: i64,
    description: String,
    installed_at: Option<String>,
}

struct AdvisoryLockGuard {
    pool: PgPool,
    key: i64,
}

impl AdvisoryLockGuard {
    async fn acquire(pool: &PgPool, key: i64) -> anyhow::Result<Self> {
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(pool)
            .await
            .with_context(|| format!("Failed to acquire PostgreSQL advisory lock {key:#x}"))?;

        Ok(Self {
            pool: pool.clone(),
            key,
        })
    }
}

impl Drop for AdvisoryLockGuard {
    fn drop(&mut self) {
        let pool = self.pool.clone();
        let key = self.key;

        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(key)
                    .execute(&pool)
                    .await;
            });
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => process::exit(0),
        Err(err) => {
            eprintln!("❌ kms-migrate failed: {err:#}");
            error!(error = ?err, "Migration CLI failed");
            process::exit(1);
        }
    }
}

fn default_command() -> Commands {
    Commands::Run { dry_run: false }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let command = cli.command.unwrap_or_else(default_command);
    let migration_dir = Path::new("migrations");

    let db_config = DatabaseConfig::from_env()
        .context("Failed to load database configuration from environment")?;

    let pool = wait_for_database_ready(&db_config, DB_READY_RETRIES, DB_READY_BACKOFF)
        .await
        .context(
            "Database is not ready after retrying; PostgreSQL did not become healthy in time",
        )?;

    match command {
        Commands::Status => {
            print_status(&pool, migration_dir, &db_config).await?;
            Ok(())
        }
        Commands::Run { dry_run } => {
            let lock = AdvisoryLockGuard::acquire(&pool, MIGRATION_LOCK_KEY).await?;

            let result = tokio::select! {
                result = run_migration_command(&pool, migration_dir, dry_run) => result,
                _ = wait_for_exit_signal() => {
                    bail!("Termination signal received; exiting before applying migrations")
                }
            };

            drop(lock);
            result
        }
    }
}

async fn wait_for_database_ready(
    db_config: &DatabaseConfig,
    attempts: usize,
    backoff: Duration,
) -> anyhow::Result<PgPool> {
    let conn_str = db_config.connection_string();

    for attempt in 1..=attempts {
        match PgPoolOptions::new()
            .max_connections(db_config.pool_size)
            .connect(&conn_str)
            .await
        {
            Ok(pool) => {
                match sqlx::query("SELECT 1").fetch_one(&pool).await {
                    Ok(_) => {
                        info!(attempt, host = %db_config.host, port = %db_config.port, "PostgreSQL is ready for migrations");
                        return Ok(pool);
                    }
                    Err(err) => {
                        warn!(attempt, host = %db_config.host, port = %db_config.port, error = ?err, "Database accepts TCP connection but is not yet ready");
                    }
                }
                pool.close().await;
            }
            Err(err) => {
                warn!(attempt, host = %db_config.host, port = %db_config.port, error = ?err, "Unable to connect to PostgreSQL yet; retrying");
            }
        }

        if attempt < attempts {
            sleep(backoff).await;
        }
    }

    Err(anyhow!(
        "Timed out after {} attempts while waiting for PostgreSQL at {}:{}",
        attempts,
        db_config.host,
        db_config.port,
    ))
}

async fn run_migration_command(
    pool: &PgPool,
    migration_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<()> {
    let local_migrations = list_local_migrations(migration_dir)?;
    let applied = fetch_applied_migrations(pool).await?;
    let applied_by_version: HashMap<i64, AppliedMigration> = applied
        .iter()
        .map(|migration| (migration.version, migration.clone()))
        .collect();

    let pending: Vec<_> = local_migrations
        .iter()
        .filter(|migration| !applied_by_version.contains_key(&migration.version))
        .cloned()
        .collect();

    if dry_run {
        println!("🔎 Dry run: {} pending migration(s) found.", pending.len());
        if pending.is_empty() {
            println!("✅ No pending migrations.");
            return Ok(());
        }

        for migration in pending {
            println!("  - {} ({})", migration.version, migration.description);
        }
        return Ok(());
    }

    if pending.is_empty() {
        println!("✅ No pending migrations to apply.");
        return Ok(());
    }

    println!("🚀 Applying {} migration(s)...", pending.len());
    for migration in &pending {
        println!("  - {} ({})", migration.version, migration.description);
    }

    let migrator = sqlx::migrate::Migrator::new(migration_dir)
        .await
        .context("Failed to load migration files from disk")?;

    migrator
        .run(pool)
        .await
        .context("Migration execution failed")?;

    println!("✅ Migration runner completed successfully.");
    Ok(())
}

async fn print_status(
    pool: &PgPool,
    migration_dir: &Path,
    db_config: &DatabaseConfig,
) -> anyhow::Result<()> {
    let local_migrations = list_local_migrations(migration_dir)?;
    let applied = fetch_applied_migrations(pool).await?;
    let applied_by_version: HashMap<i64, AppliedMigration> = applied
        .iter()
        .map(|migration| (migration.version, migration.clone()))
        .collect();

    println!("=== KMS migration status ===");
    println!(
        "Database: {}:{} / {}",
        db_config.host, db_config.port, db_config.name
    );

    println!("\nApplied migrations:");
    let mut applied_count = 0;
    for migration in &applied {
        println!(
            "  ✅ {} | {} | {}",
            migration.version,
            migration.description,
            migration
                .installed_at
                .clone()
                .unwrap_or_else(|| "n/a".to_owned())
        );
        applied_count += 1;
    }
    if applied_count == 0 {
        println!("  (none)");
    }

    println!("\nPending migrations:");
    let mut pending_count = 0;
    for migration in &local_migrations {
        if applied_by_version.contains_key(&migration.version) {
            continue;
        }
        println!("  ⏳ {} | {}", migration.version, migration.description);
        pending_count += 1;
    }
    if pending_count == 0 {
        println!("  (none)");
    }

    println!(
        "\nTotal local migrations: {} | applied: {} | pending: {}",
        local_migrations.len(),
        applied.len(),
        pending_count
    );
    Ok(())
}

fn list_local_migrations(migration_dir: &Path) -> anyhow::Result<Vec<LocalMigration>> {
    let mut migrations = vec![];

    for entry in fs::read_dir(migration_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }

        let file_name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let version_text = file_name.split('_').next().unwrap_or(file_name);
        let version = match version_text.parse::<i64>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let description = file_name.replace("_", " ");
        migrations.push(LocalMigration {
            version,
            description,
            path,
        });
    }

    migrations.sort_by_key(|migration| migration.version);
    Ok(migrations)
}

async fn fetch_applied_migrations(pool: &PgPool) -> anyhow::Result<Vec<AppliedMigration>> {
    let rows = match sqlx::query(
        "SELECT version, description, installed_at FROM _sqlx_migrations ORDER BY version ASC",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            if matches!(
                error.as_database_error().and_then(|db_error| db_error.code()),
                Some(code) if code == "42P01"
            ) {
                return Ok(vec![]);
            }
            return Err(error).context("Failed to query applied migrations from _sqlx_migrations");
        }
    };

    let mut migrations = Vec::with_capacity(rows.len());
    for row in rows {
        let version: i64 = row.try_get("version")?;
        let description: String = row.try_get("description")?;
        let installed_at: Option<String> = row.try_get("installed_at")?;

        migrations.push(AppliedMigration {
            version,
            description,
            installed_at,
        });
    }

    Ok(migrations)
}

async fn wait_for_exit_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint =
            signal(SignalKind::interrupt()).expect("sigint handler should be installed");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("sigterm handler should be installed");

        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn missing_args_leaves_command_unset_but_default_run_is_defined() {
        let cli = Cli::try_parse_from(["kms-migrate"]).unwrap();
        assert!(cli.command.is_none());
        assert!(matches!(
            super::default_command(),
            Commands::Run { dry_run: false }
        ));
    }

    #[test]
    fn dry_run_flag_is_supported_on_run_command() {
        let cli = Cli::try_parse_from(["kms-migrate", "run", "--dry-run"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Run { dry_run: true })));
    }

    #[test]
    fn migration_lock_key_matches_kms_migrate_constant() {
        assert_eq!(super::MIGRATION_LOCK_KEY, 0x4B4D535F4D494752_i64);
    }
}
