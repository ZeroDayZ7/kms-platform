use crate::domain::keys::models::ServiceId; // Import na górze pliku
use crate::domain::keys::repository::KeyRepository;
use crate::server::state::KeyCache;
use chrono::Utc;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

pub async fn run_cache_cleanup<K>(
    key_cache: Arc<KeyCache>,
    key_repo: Arc<K>,
    cleanup_interval: Duration,
    shutdown: CancellationToken,
) where
    K: KeyRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("Wygaszanie zadania run_cache_cleanup");
                    break;
                }
                _ = async {
                    let keys = key_cache.keys_snapshot();
                    let now = Utc::now();

                    for k in keys {
                        // Czysto i czytelnie dzięki importowi ServiceId na górze
                        let service = ServiceId(k.target_service.clone());
                        let algo = k.algorithm;

                        if let Ok(None) = key_repo.get_active_or_valid_deprecated_key(&service, algo, now).await {
                            key_cache.remove_all_for_service(&service);
                        }
                    }

                    // Dynamiczny czas oczekiwania przekazany z konfiguracji
                    sleep(cleanup_interval).await;
                } => {}
            }
        }
    });
}
