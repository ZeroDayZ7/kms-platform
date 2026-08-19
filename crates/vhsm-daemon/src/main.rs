mod crypto;
mod handler;
mod listener;
mod state;

use std::sync::Arc;
use tokio::sync::RwLock;

use state::VhsmState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon w trybie zero-trust...");

    let state = Arc::new(RwLock::new(VhsmState::new()));

    #[cfg(unix)]
    {
        listener::run_unix_listener(state).await?;
    }

    #[cfg(not(unix))]
    {
        let _ = state;
        tracing::warn!("Środowisko nie-UNIX - vHSM działa w trybie mock.");
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
