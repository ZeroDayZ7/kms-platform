use anyhow::Context;
use axum::Router;
use std::net::SocketAddr;
use tokio::{signal, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn serve(
    router: Router,
    addr: SocketAddr,
    shutdown_timeout: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    info!("🚀 Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    server
        .with_graceful_shutdown(shutdown_signal(shutdown_timeout, shutdown_token.clone()))
        .await
        .context("Axum server error")?;

    Ok(())
}

async fn shutdown_signal(timeout: u64, shutdown_token: CancellationToken) {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            warn!(error = %error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        let mut terminate_signal = match signal::unix::signal(signal::unix::SignalKind::terminate())
        {
            Ok(signal) => signal,
            Err(error) => {
                warn!(error = %error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        };

        terminate_signal.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Ctrl+C received"),
        _ = terminate => info!("🛑 SIGTERM received"),
    }

    shutdown_token.cancel();
    info!("⏳ Graceful shutdown started ({}s)", timeout);

    tokio::time::sleep(Duration::from_secs(timeout)).await;

    warn!("⚠️ Shutdown timeout reached");
}
