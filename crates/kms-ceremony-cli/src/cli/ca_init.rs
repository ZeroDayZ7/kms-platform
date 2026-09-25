use anyhow::Result;
use kms_core::hsm::client::generate_root_ca_via_hsm;
use kms_db::repositories::RootCaQueries;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use chrono::Utc;

pub async fn handle_ca_init(socket_path: String, ca_tag: String) -> Result<()> {
    // Obtain DB pool from environment (reuse existing pattern if available)
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&db_url).await?;

    // Check if CA exists
    let exists = RootCaQueries::exists_by_tag(&pool, &ca_tag).await?;
    if exists {
        println!("Root CA '{}' already exists. No action taken.", ca_tag);
        return Ok(());
    }

    // Request vHSM to generate root CA key
    let (encrypted_private_key, public_key, master_key_version, algorithm) =
        generate_root_ca_via_hsm(&socket_path, "ECDSA_P256", None).await?;

    // For now certificate is empty placeholder; X.509 generation happens later
    let cert_pem = "".to_string();
    let serial = Uuid::new_v4().to_string();
    // Mark as INITIALIZING until certificate is generated
    let status = "INITIALIZING".to_string();
    let now = Utc::now();
    let expires_at: Option<chrono::DateTime<Utc>> = None;

    // Persist
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;
    let id = Uuid::new_v4();
    // Find active KEK for kms-system (use existing KEK selection mechanism)
    let kek_row = kms_db::repositories::CredentialQueries::fetch_latest_kek_id(&pool, "kms-system").await?;
    let (kek_id, kek_version) = match kek_row {
        Some((id, ver)) => (id, ver),
        None => anyhow::bail!("No active KEK found for kms-system; cannot persist Root CA"),
    };

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
        anyhow::bail!("Failed to insert Root CA")
    }
    tx.commit().await?;

    println!("Root CA '{}' initialized (id={}).", ca_tag, id);
    Ok(())
}
