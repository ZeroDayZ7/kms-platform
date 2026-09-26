use anyhow::Result;
use chrono::{Duration, Utc};
use kms_core::hsm::client::generate_root_ca_via_hsm;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use kms_db::repositories::{CredentialQueries, RootCaQueries};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Acquire a pg advisory transaction lock for a textual key.
async fn acquire_ca_tag_tx_lock(
    tx: &mut Transaction<'_, Postgres>,
    ca_tag: &str,
) -> Result<(), sqlx::Error> {
    // Use hashtext to compute consistent 64-bit hash in Postgres side via text hashing.
    // We'll call pg_advisory_xact_lock with a signed bigint derived from a 64-bit hash.
    // Simpler: use Postgres hashtext() and mod into bigint space client-side via query.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(ca_tag)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

pub async fn handle_ca_init(socket_path: String, ca_tag: String) -> Result<()> {
    // Obtain DB pool from environment
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&db_url).await?;

    // Start a transaction so advisory lock is held for the duration of the decision
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Acquire advisory lock scoped to this transaction to prevent concurrent initializations
    acquire_ca_tag_tx_lock(&mut tx, &ca_tag).await?;

    // Re-check existence while holding the lock
    let exists = RootCaQueries::exists_by_tag(&pool, &ca_tag).await?;
    if exists {
        // Nothing to do; commit and return
        tx.commit().await?;
        println!("Root CA '{}' already exists. No action taken.", ca_tag);
        return Ok(());
    }

    // Fetch KEK info before calling vHSM
    let kek_row = CredentialQueries::fetch_latest_kek_id(&pool, "kms-system").await?;
    let (kek_id, _kek_version) = match kek_row {
        Some((id, ver)) => (id, ver),
        None => anyhow::bail!("No active KEK found for kms-system; cannot persist Root CA"),
    };

    // Now call vHSM to generate the root CA keypair - do this while holding the advisory lock
    let (encrypted_private_key, public_key, master_key_version, algorithm, certificate_pem) =
        generate_root_ca_via_hsm(&socket_path, "ECDSA_P256", None).await?;

    let encrypted_private_key = encrypted_private_key.to_vec();
    let public_key = public_key.to_vec();
    let cert_pem = certificate_pem
        .ok_or_else(|| anyhow::anyhow!("vHSM did not return certificate PEM"))?;
    let serial = Uuid::new_v4().to_string();
    let status = "ACTIVE".to_string();
    let now = Utc::now();
    // Set a long lifetime for root CA (e.g., 20 years)
    let expires_at = Some(now + Duration::days(365 * 20));

    // Persist atomically inside the transaction
    let id = Uuid::new_v4();
    let inserted = RootCaQueries::insert_root_ca(
        &mut tx,
        id,
        &ca_tag,
        &algorithm,
        &public_key,
        &encrypted_private_key,
        kek_id,
        master_key_version as i32,
        &cert_pem,
        &serial,
        &status,
        now,
        expires_at,
    )
    .await?;

    if !inserted {
        tx.rollback().await?;
        println!(
            "Root CA '{}' already exists (race). No action taken.",
            ca_tag
        );
        return Ok(());
    }

    // Send ceremony registration to kms-service instead of writing directly to DB
    let service_url = std::env::var("KMS_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let client = reqwest::Client::new();
    let manifest = serde_json::json!({
        "operation": "ca_init",
        "ca_tag": ca_tag,
        "root_ca_id": id,
        "kek_id": kek_id,
        "algorithm": algorithm,
        "public_key_b64": BASE64_ENGINE.encode(&public_key),
        "encrypted_private_key_b64": BASE64_ENGINE.encode(&encrypted_private_key),
        "kek_version": master_key_version as i32,
        "certificate_pem": cert_pem,
        "serial": serial,
        "status": status,
    });

    let resp = client
        .post(format!("{}/api/v1/ceremonies", service_url))
        .json(&manifest)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("kms-service returned error: {}", resp.text().await.unwrap_or_default())
    }

    tx.commit().await?;

    println!("Root CA '{}' initialized (id={}).", ca_tag, id);
    Ok(())
}
