use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand};
use kms_service::application::use_cases::rewrap_keys::{RewrapKeysInput, rewrap_keys};
use kms_service::bootstrap::{bootstrap_keys, wait_for_vhsm_unsealed};
use kms_service::config;
use kms_service::domain::{
    audit::{
        AuditRepository,
        models::{AuditAction, AuditLog, AuditStatus},
    },
    keys::models::{KeyAlgorithm, ServiceId},
};
use kms_service::infrastructure::postgres::PgAuditRepository;
use kms_service::server::{self, state::AppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(name = "kms-service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    Rewrap {
        #[arg(long)]
        target_version: i32,
        #[arg(long, default_value_t = 100)]
        batch_size: usize,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_command(cli).await {
        eprintln!("❌ KRYTYCZNY BŁĄD: {:#}", e);
        error!(error = ?e, "❌ Fatal application error");
        std::process::exit(1);
    }
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
    let settings = Arc::new(config::load().context("Failed to load configuration")?);
    server::logger::init_logging(&settings.log);
    info!("⚙️ Configuration loaded");

    match cli.command {
        Command::Serve => {
            // 1. Sprawdzamy gotowość HSM przed podłączeniem do bazy danych i bootstrapem
            wait_for_vhsm_unsealed(&settings.crypto.hsm_socket_path).await?;

            let shutdown_token = CancellationToken::new();

            // 2. Inicjalizacja połączenia z bazy DB / Redis
            let state = AppState::new(settings.clone(), shutdown_token.clone())
                .await
                .context("Krytyczny błąd inicjalizacji AppState")?;

            let startup_audit = PgAuditRepository::new(state.db.clone());
            startup_audit
                .record(AuditLog::new(
                    uuid::Uuid::now_v7(),
                    ServiceId("kms-service".to_string()),
                    ServiceId("kms-service".to_string()),
                    AuditAction::SystemStarted,
                    KeyAlgorithm::AES256GCM,
                    AuditStatus::Success,
                    Some("service startup initialized".to_string()),
                    Some(uuid::Uuid::now_v7().to_string()),
                    Some(uuid::Uuid::now_v7().to_string()),
                    Some("instance".to_string()),
                    Some("service_startup".to_string()),
                    Utc::now(),
                ))
                .await
                .context("Failed to record startup audit event")?;

            info!("🧠 Application state initialized");

            // 3. Generowanie i zaszyfrowanie brakujących kluczy w DB
            bootstrap_keys(
                &settings.acl,
                state.key_repo.clone(),
                state.crypto_service.clone(),
                state.key_cache.clone(),
            )
            .await
            .context("Krytyczny błąd bootstrapu kluczy KMS")?;

            let addr: SocketAddr = format!("{}:{}", settings.server.host, settings.server.port)
                .parse()
                .context("Invalid server address")?;

            info!(
                spiffe_enabled = settings.auth.spiffe.enabled,
                tls_cert_path = ?settings.auth.spiffe.tls_cert_path,
                tls_key_path = ?settings.auth.spiffe.tls_key_path,
                trust_bundle_path = ?settings.auth.spiffe.trust_bundle_path,
                "🔍 Weryfikacja parametrów mTLS dla SPIFFE"
            );

            if settings.auth.spiffe.enabled
                && !(settings.auth.spiffe.tls_cert_path.is_some()
                    && settings.auth.spiffe.tls_key_path.is_some()
                    && settings.auth.spiffe.trust_bundle_path.is_some())
            {
                error!(
                    cert_missing = settings.auth.spiffe.tls_cert_path.is_none(),
                    key_missing = settings.auth.spiffe.tls_key_path.is_none(),
                    trust_bundle_missing = settings.auth.spiffe.trust_bundle_path.is_none(),
                    "❌ Konfiguracja mTLS jest niekompletna"
                );

                anyhow::bail!(
                    "SPIFFE is enabled but mTLS TLS configuration is incomplete: cert, key, and trust bundle are required"
                );
            }

            let app = server::router(state.clone());
            info!("🚀 Server starting on {}", addr);
            if settings.auth.spiffe.enabled {
                server::http::serve_mtls(
                    app,
                    addr,
                    settings.clone(),
                    settings.server.shutdown_timeout,
                    shutdown_token.clone(),
                )
                .await
                .context("mTLS HTTP server crashed")?;
            } else {
                server::http::serve(
                    app,
                    addr,
                    settings.server.shutdown_timeout,
                    shutdown_token.clone(),
                )
                .await
                .context("HTTP server crashed")?;
            }

            state.shutdown().await;
            info!("✅ Server shutdown complete");
        }
        Command::Rewrap {
            target_version,
            batch_size,
        } => {
            wait_for_vhsm_unsealed(&settings.crypto.hsm_socket_path).await?;

            let state = AppState::new(settings.clone(), CancellationToken::new())
                .await
                .context("Krytyczny błąd inicjalizacji AppState")?;

            let count = rewrap_keys(
                state.key_repo.clone(),
                state.crypto_service.clone(),
                RewrapKeysInput {
                    target_master_version: target_version,
                    batch_size,
                },
            )
            .await
            .context("Failed to rewrap keys")?;

            info!(
                "✅ Rewrapped {} keys to master version {}",
                count, target_version
            );
        }
    }

    Ok(())
}
