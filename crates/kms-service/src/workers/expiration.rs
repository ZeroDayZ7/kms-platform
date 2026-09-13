use chrono::Utc;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use crate::domain::audit::models::{AuditAction, AuditLog, AuditStatus};
use crate::domain::audit::repository::AuditRepository;
use crate::domain::keys::repository::KeyRepository;

pub async fn run_expiration_worker<K, A>(
    key_repo: Arc<K>,
    audit_repo: Arc<A>,
    check_interval: Duration,
    shutdown_token: CancellationToken,
) where
    K: KeyRepository + Send + Sync + 'static,
    A: AuditRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Expiration worker shutdown requested");
                    break;
                }
                _ = async {
                    if let Err(e) = process_expirations(Arc::clone(&key_repo), Arc::clone(&audit_repo)).await {
                        tracing::error!("Expiration worker error: {:?}", e);
                    }
                    sleep(check_interval).await;
                } => {}
            }
        }
    });
}

async fn process_expirations<K, A>(
    key_repo: Arc<K>,
    audit_repo: Arc<A>,
) -> Result<(), Box<dyn std::error::Error>>
where
    K: KeyRepository + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    let now = Utc::now();
    let expired = key_repo.get_deprecated_keys_expired(now).await?;

    for key in expired {
        key_repo
            .update_key_status(
                &key.id,
                crate::domain::keys::models::KeyStatus::Expired,
                None,
            )
            .await?;

        let audit = AuditLog::new(
            uuid::Uuid::now_v7(),
            key.service_id.clone(),
            key.service_id.clone(),
            AuditAction::KeyExpired,
            key.algorithm,
            AuditStatus::Success,
            AuditLog::sanitize_reason(Some("Deprecated period expired; key expired automatically")),
            None,
            None,
            Some(key.id.to_string()),
            Some("key_expired".to_string()),
            Utc::now(),
        );

        audit_repo.record(audit).await?;
    }

    Ok(())
}
