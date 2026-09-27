use anyhow::Result;
use chrono::{Duration, Utc};
use kms_core::hsm::client::generate_root_ca_via_hsm;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use serde::Serialize;
use uuid::Uuid;

// CLI is thin: no DB access. The service will perform DB transaction and locking.

#[derive(Serialize)]
struct CaInitManifest {
    operation: &'static str,
    ca_tag: String,
    algorithm: String,
    public_key_b64: String,
    encrypted_private_key_b64: String,
    certificate_pem: String,
    serial: String,
    status: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn handle_ca_init(socket_path: String, ca_tag: String) -> Result<()> {
    // Call vHSM to generate the root CA keypair
    let (encrypted_private_key, public_key, _master_key_version, algorithm, certificate_pem) =
        generate_root_ca_via_hsm(&socket_path, "ECDSA_P256", None).await?;

    let encrypted_private_key = encrypted_private_key.to_vec();
    let public_key = public_key.to_vec();
    let cert_pem = certificate_pem
        .ok_or_else(|| anyhow::anyhow!("vHSM did not return certificate PEM"))?;
    let serial = Uuid::new_v4().to_string();
    let status = "ACTIVE".to_string();
    let now = Utc::now();
    let expires_at = Some(now + Duration::days(365 * 20));

    let manifest = CaInitManifest {
        operation: "ca_init",
        ca_tag: ca_tag.clone(),
        algorithm: algorithm.clone(),
        public_key_b64: BASE64_ENGINE.encode(&public_key),
        encrypted_private_key_b64: BASE64_ENGINE.encode(&encrypted_private_key),
        certificate_pem: cert_pem.clone(),
        serial: serial.clone(),
        status: status.clone(),
        expires_at,
    };

    let service_url = std::env::var("KMS_CLI__SERVICE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/ceremonies/ca-init", service_url))
        .json(&manifest)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("kms-service returned error: {}", resp.text().await.unwrap_or_default())
    }

    println!("Root CA '{}' initialized (serial={}).", ca_tag, serial);
    Ok(())
}
