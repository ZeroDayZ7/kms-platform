use anyhow::Context;
use axum::Router;
use std::net::SocketAddr;
use tokio::{signal, time::Duration};
use tracing::{info, warn};

pub async fn serve(router: Router, addr: SocketAddr, shutdown_timeout: u64) -> anyhow::Result<()> {
    info!("🚀 Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    server
        .with_graceful_shutdown(shutdown_signal(shutdown_timeout))
        .await
        .context("Axum server error")?;

    Ok(())
}

async fn shutdown_signal(timeout: u64) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Ctrl+C received"),
        _ = terminate => info!("🛑 SIGTERM received"),
    }

    info!("⏳ Graceful shutdown started ({}s)", timeout);

    tokio::time::sleep(Duration::from_secs(timeout)).await;

    warn!("⚠️ Shutdown timeout reached");
}
