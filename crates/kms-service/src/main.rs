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

            // Spawn a Unix domain socket listener for external KMS clients (plugin).
            // This ensures the socket at /run/kms/kms.sock exists and is accepting
            // connections before SPIRE plugin attempts to connect.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                use std::path::Path;
                use tokio::net::UnixListener;

                let socket_path = settings
                    .server
                    .unix_socket_path
                    .clone()
                    .unwrap_or_else(|| "/run/kms/kms.sock".to_string());

                if let Some(parent) = Path::new(&socket_path).parent() {
                    if let Err(err) = tokio::fs::create_dir_all(parent).await {
                        tracing::warn!(error = ?err, "Failed to create parent dir for KMS socket: {}", parent.display());
                    }
                }

                if Path::new(&socket_path).exists() {
                    // Best-effort remove stale socket file
                    if let Err(err) = tokio::fs::remove_file(&socket_path).await {
                        tracing::warn!(error = ?err, "Failed to remove existing KMS socket file {}", socket_path);
                    }
                }

                match UnixListener::bind(&socket_path) {
                    Ok(listener) => {
                        // set permissive socket permissions so other containers/users can connect
                        if let Err(err) = std::fs::set_permissions(
                            &socket_path,
                            std::fs::Permissions::from_mode(0o666),
                        ) {
                            tracing::warn!(error = ?err, "Failed to set permissions on KMS socket {}");
                        }

                        tracing::info!(socket = %socket_path, "KMS UDS listener bound");

                        // Spawn accept loop that handles the simple length-prefixed JSON protocol
                        let state_for_uds = state.clone();
                        tokio::spawn(async move {
                            loop {
                                match listener.accept().await {
                                    Ok((mut stream, _)) => {
                                        let state_conn = state_for_uds.clone();
                                        tokio::spawn(async move {
                                            use tokio::io::{AsyncReadExt, AsyncWriteExt};

                                            // Read 4-byte BE length
                                            let mut len_buf = [0u8; 4];
                                            if let Err(err) = stream.read_exact(&mut len_buf).await
                                            {
                                                tracing::warn!(error = ?err, "failed to read frame length from KMS UDS client");
                                                return;
                                            }
                                            let len = u32::from_be_bytes(len_buf) as usize;
                                            // Limit sanity check
                                            if len > 10 * 1024 * 1024 {
                                                tracing::warn!(
                                                    len,
                                                    "KMS UDS request too large, rejecting"
                                                );
                                                return;
                                            }
                                            let mut payload = vec![0u8; len];
                                            if let Err(err) = stream.read_exact(&mut payload).await
                                            {
                                                tracing::warn!(error = ?err, "failed to read payload from KMS UDS client");
                                                return;
                                            }

                                            // Try to deserialize plugin KMS sign request
                                            #[derive(serde::Deserialize)]
                                            struct KmsSignRequest {
                                                csr_pem: String,
                                                ca_tag: String,
                                                validity_days: u32,
                                                caller_service: String,
                                            }

                                            #[derive(serde::Serialize)]
                                            struct KmsSignResponse {
                                                certificate_pem: String,
                                                root_certificate_pem: Option<String>,
                                            }

                                            let req: KmsSignRequest = match serde_json::from_slice(
                                                &payload,
                                            ) {
                                                Ok(r) => r,
                                                Err(err) => {
                                                    tracing::warn!(error = ?err, "failed to deserialize KMS sign request from UDS client");
                                                    return;
                                                }
                                            };

                                            // Execute SignIntermediateCa use case
                                            let audit_repo =
                                                PgAuditRepository::new(state_conn.db.clone());
                                            let audit_service = Arc::new(
                                                crate::domain::audit::service::AuditService::new(
                                                    Arc::new(audit_repo),
                                                ),
                                            );
                                            let usecase = crate::application::use_cases::sign_intermediate_ca::SignIntermediateCaUseCase::new(audit_service);

                                            let input = crate::application::use_cases::sign_intermediate_ca::SignIntermediateCaInput {
                                                caller_service: crate::domain::keys::models::ServiceId(req.caller_service),
                                                ca_tag: req.ca_tag.clone(),
                                                csr_pem: req.csr_pem.clone(),
                                                validity_days: req.validity_days,
                                            };

                                            let response = match usecase
                                                .execute(&state_conn, input)
                                                .await
                                            {
                                                Ok(out) => KmsSignResponse {
                                                    certificate_pem: out.certificate_pem,
                                                    root_certificate_pem: None,
                                                },
                                                Err(err) => {
                                                    tracing::error!(error = ?err, "SignIntermediateCa use case failed");
                                                    // return an error response encoded as JSON HsmResponse::Error-like
                                                    let err_resp = kms_core::hsm::protocol::HsmResponse::Error { code: 500, message: format!("SignIntermediateCa failed: {}", err) };
                                                    if let Ok(err_payload) =
                                                        serde_json::to_vec(&err_resp)
                                                    {
                                                        let frame_len = (err_payload.len() as u32)
                                                            .to_be_bytes();
                                                        let _ = stream.write_all(&frame_len).await;
                                                        let _ =
                                                            stream.write_all(&err_payload).await;
                                                    }
                                                    return;
                                                }
                                            };

                                            // Serialize and respond
                                            let res_payload = match serde_json::to_vec(&response) {
                                                Ok(p) => p,
                                                Err(err) => {
                                                    tracing::error!(error = ?err, "failed to serialize KMS sign response");
                                                    return;
                                                }
                                            };

                                            let frame_len =
                                                (res_payload.len() as u32).to_be_bytes();
                                            if let Err(err) = stream.write_all(&frame_len).await {
                                                tracing::warn!(error = ?err, "failed to write response length to KMS UDS client");
                                                return;
                                            }
                                            if let Err(err) = stream.write_all(&res_payload).await {
                                                tracing::warn!(error = ?err, "failed to write response payload to KMS UDS client");
                                                return;
                                            }
                                        });
                                    }
                                    Err(err) => {
                                        tracing::error!(error = ?err, "KMS UDS listener accept error");
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = ?err, "Failed to bind KMS UDS socket at {}", socket_path)
                    }
                }
            }

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
