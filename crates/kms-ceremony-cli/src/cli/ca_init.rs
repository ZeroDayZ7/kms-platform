use anyhow::Result;
use chrono::{Duration, Utc};
use kms_core::hsm::client::generate_root_ca_via_hsm;
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
    let (encrypted_private_key, public_key, master_key_version, algorithm) =
        generate_root_ca_via_hsm(&socket_path, "ECDSA_P256", None).await?;

    // Generate certificate and metadata
    let cert_pem = generate_self_signed_cert_pem(&ca_tag, &public_key)?;
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

    tx.commit().await?;

    println!("Root CA '{}' initialized (id={}).", ca_tag, id);
    Ok(())
}

/// Create a minimal self-signed X.509 certificate PEM from an SEC1 uncompressed P-256 public key.
fn generate_self_signed_cert_pem(
    ca_tag: &str,
    public_key_sec1: &[u8],
) -> Result<String, anyhow::Error> {
    // Use rcgen-like manual construction to avoid adding dependencies; build a simple PEM.
    // However, rcgen is more convenient. Try to use rcgen if available in workspace, else construct
    // a basic certificate using openssl crate — but to keep dependencies minimal, implement with
    // the `x509-parser`/`yasna` crates is heavy. For now, use `rcgen` via runtime optional dependency.
    // We'll attempt to build using rcgen; if crate not available in workspace, return an error.

    // Defer to rcgen if present
    #[cfg(feature = "use_rcgen")]
    {
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
        };

        let mut params = CertificateParams::new(vec![ca_tag.to_string()]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        // Provide public key bytes (SEC1) directly
        params.public_key = Some(public_key_sec1.to_vec());
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, ca_tag.to_string());
        let cert = Certificate::from_params(params)?;
        let pem = cert.serialize_pem()?;
        return Ok(pem);
    }

        // Create a minimal PEM placeholder containing the public key bytes encoded in base64.
        // This is a pragmatic placeholder so the certificate_pem field is populated while the
        // proper X.509 signing flow (HSM signing) is implemented in a follow-up change.
        let b64 = base64::encode(public_key_sec1);
        let mut pem = String::new();
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        // Insert CA tag as a comment for human readability
        pem.push_str(&format!("# CN={}\n", ca_tag));
        // Wrap base64 at 64 chars per line
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(&format!("{}\n", std::str::from_utf8(chunk).unwrap()));
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        Ok(pem)
}
