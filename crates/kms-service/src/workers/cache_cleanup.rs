use crate::domain::keys::repository::KeyRepository;
use crate::server::state::KeyCache;
use chrono::{Duration as ChronoDuration, Utc};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

pub async fn run_cache_cleanup<K>(
    key_cache: Arc<KeyCache>,
    key_repo: Arc<K>,
    grace_minutes: i64,
    shutdown: CancellationToken,
) where
    K: KeyRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = async {
                    // Iterate keys and validate against repository state
                    // For simplicity, we remove any key that no longer has an active or valid deprecated key
                    // Note: This may be optimized to check timestamps instead.
                    // Acquire a snapshot of keys
                    let keys = key_cache.keys_snapshot();
                    for k in keys {
                        let service = crate::domain::keys::models::ServiceId(k.target_service.clone());
                        let algo = k.algorithm;
                        let now = Utc::now();
                        if let Ok(opt) = key_repo.get_active_or_valid_deprecated_key(&service, algo, now).await {
                            if opt.is_none() {
                                // remove from cache
                                key_cache.remove_all_for_service(&service);
                            }
                        }
                    }
                    sleep(Duration::from_secs(60)).await;
                } => {}
            }
        }
    });
}
