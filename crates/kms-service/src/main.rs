use anyhow::Context;
use clap::{Parser, Subcommand};
use kms_service::application::use_cases::rewrap_keys::{RewrapKeysInput, rewrap_keys};
use kms_service::bootstrap::{bootstrap_keys, wait_for_vhsm_unsealed};
use kms_service::config;
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

            let app = server::router(state.clone());
            info!("🚀 Server starting on {}", addr);
            server::http::serve(
                app,
                addr,
                settings.server.shutdown_timeout,
                shutdown_token.clone(),
            )
            .await
            .context("HTTP server crashed")?;

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
