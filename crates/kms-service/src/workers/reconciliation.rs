use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

pub async fn run_reconciliation_worker(
    db: PgPool,
    check_interval: Duration,
    shutdown_token: CancellationToken,
) {
    let db = Arc::new(db);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!(target: "workers::reconciliation", "Provisioning reconciliation worker shutdown requested");
                    break;
                }
                _ = async {
                    if let Err(err) = reconcile_stale_provisioning(Arc::clone(&db)).await {
                        tracing::warn!(target: "workers::reconciliation", error = %err, "Provisioning reconciliation finished with warnings");
                    }
                    sleep(check_interval).await;
                } => {}
            }
        }
    });
}

async fn reconcile_stale_provisioning(db: Arc<PgPool>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = Utc::now();
    let stale = sqlx::query_scalar::<_, String>(
        r#"
        SELECT id::text
        FROM provisioned_credentials
        WHERE status IN ('PENDING', 'PROVISIONING', 'FAILED', 'REVOKING')
          AND created_at < $1 - INTERVAL '5 minutes'
        ORDER BY created_at ASC
        LIMIT 100
        "#,
    )
    .bind(now)
    .fetch_all(db.as_ref())
    .await?;

    for id in stale {
        tracing::warn!(target: "workers::reconciliation", credential_id = %id, "Found stale provisioning record; cleanup should be scheduled or retried");
    }

    Ok(())
}
