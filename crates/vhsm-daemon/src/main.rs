mod crypto;
mod handler;
mod listener;
mod pki;
mod state;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use state::VhsmState;

/// Maksymalny czas na dokończenie procedury Unseal (15 minut)
const UNSEAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon w trybie zero-trust...");

    let state = Arc::new(RwLock::new(VhsmState::new()));

    // --- TASK UNSEAL TIMEOUT CHECKER ---
    let state_lock_checker = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let mut guard = state_lock_checker.write().await;

            if let Some(started_at) = guard.unseal_started_at
                && guard.master_key.is_none()
                && started_at.elapsed() >= UNSEAL_TIMEOUT
            {
                tracing::warn!(
                    "[SECURITY] Przekroczono limit czasowy ceremonii Unseal (15 min). Resetowanie próby!"
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
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
