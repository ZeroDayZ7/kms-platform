mod crypto;
mod handler;
mod listener;
mod state;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use state::VhsmState;

const AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(15 * 60); // 15 minut

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon w trybie zero-trust...");

    let state = Arc::new(RwLock::new(VhsmState::new()));

    // --- TASK AUTO-LOCK ---
    let state_lock_checker = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30)); // sprawdzaj co 30 sek
        loop {
            interval.tick().await;
            let mut guard = state_lock_checker.write().await;
            if guard.initialized && guard.last_activity.elapsed() >= AUTO_LOCK_TIMEOUT {
                tracing::warn!(
                    "[SECURITY] Osiągnięto limit bezczynności (15 min). Blokowanie vHSM i czyszczenie RAM!"
                );
                guard.zeroize_key();
            }
        }
    });

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
