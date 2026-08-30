use crate::cli::hmac::{build_signed_request_headers, resolve_cli_config};
use anyhow::{Context, Result, bail};
use dialoguer::Password;
use kms_core::crypto::aes::decrypt_bytes_with_argon2_raw;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use zeroize::{Zeroize, Zeroizing};

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MiB
const MAX_CREDENTIALS: usize = 1000;
const MAX_FIELD_LEN: usize = 1024;

// --- NOWA STRUKTURA DLA TARGET RESOURCES ---
#[derive(Debug, Deserialize, Serialize)]
pub struct TargetResourceRecord {
    pub target_name: String,
    pub target_type: String,
    pub connection_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BootstrapCredentialRecord {
    pub service_id: String,
    pub target_type: String,
    pub target_db: String,
    pub resource: Option<String>,
    pub username: String,
    pub password: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapFile {
    pub version: u32,
    #[serde(default)]
    pub target_resources: Vec<TargetResourceRecord>, // <-- DODANE
    #[serde(default)]
    pub credentials: Vec<BootstrapCredentialRecord>,
}

#[derive(Serialize)]
struct PostPayload<'a> {
    version: u32,
    target_resources: &'a [TargetResourceRecord], // <-- DODANE
    credentials: &'a [BootstrapCredentialRecord],
}

pub async fn handle_import_bootstrap(file: PathBuf, service_url: Option<String>) -> Result<()> {
    // Validate file exists and size
    let meta = fs::metadata(&file).await.context("Cannot stat file")?;
    if !meta.is_file() {
        bail!("Not a regular file: {}", file.display());
    }
    if meta.len() > MAX_FILE_SIZE {
        bail!("File too large (>5MiB): {} bytes", meta.len());
    }

    // 1. Odczytujemy surowe bajty binarne pliku `.enc`
    let content_bytes = fs::read(&file).await.context("Failed to read file")?;

    // Prompt for passphrase
    let pass = Password::new()
        .with_prompt("Passphrase to decrypt bootstrap file")
        .allow_empty_password(false)
        .interact()
        .context("Failed to read passphrase")?;

    // 2. Odszyfrowujemy surowe bajty wygenerowane przez Go (Argon2id + AES-GCM)
    let plaintext = decrypt_bytes_with_argon2_raw(&pass, &content_bytes)
        .map_err(|e| anyhow::anyhow!("bootstrap file authentication failed: {e}"))?;

    // Zeroize passphrase
    let mut pass_z = Zeroizing::new(pass);
    pass_z.zeroize();

    // 3. Parsujemy odszyfrowany ładunek JSON do struktury BootstrapFile
    let plaintext_z = Zeroizing::new(plaintext);
    let bootstrap: BootstrapFile =
        serde_json::from_slice(&plaintext_z).context("Invalid bootstrap JSON payload")?;

    // Basic validation
    if bootstrap.version != 1 {
        bail!("Unsupported bootstrap file version: {}", bootstrap.version);
    }
    if bootstrap.credentials.is_empty() && bootstrap.target_resources.is_empty() {
        bail!("No credentials nor target resources in bootstrap file");
    }
    if bootstrap.credentials.len() > MAX_CREDENTIALS {
        bail!("Too many credentials in file");
    }

    // Walidacja target_resources
    for target in &bootstrap.target_resources {
        if target.target_name.is_empty()
            || target.target_type.is_empty()
            || target.connection_url.is_empty()
        {
            bail!("Missing required fields in target resource record");
        }
    }

    for rec in &bootstrap.credentials {
        if rec.service_id.is_empty()
            || rec.target_type.is_empty()
            || rec.target_db.is_empty()
            || rec.username.is_empty()
            || rec.password.is_empty()
        {
            bail!("Missing required fields in credential record");
        }
        if rec.service_id.len() > MAX_FIELD_LEN
            || rec.target_type.len() > MAX_FIELD_LEN
            || rec.target_db.len() > MAX_FIELD_LEN
            || rec.username.len() > MAX_FIELD_LEN
            || rec.password.len() > (MAX_FIELD_LEN * 4)
        {
            bail!("Field too long in credential record");
        }
    }

    // Prepare POST to KMS
    let cfg = resolve_cli_config(service_url)?;
    let client = Client::new();
    let path = "/api/v1/admin/bootstrap/import";
    let headers = build_signed_request_headers(&cfg, "POST", path)?;

    // Budujemy pełny payload zawierający target_resources
    let payload = PostPayload {
        version: bootstrap.version,
        target_resources: &bootstrap.target_resources, // <-- PRZEKAZUJEMY DO REST API
        credentials: &bootstrap.credentials,
    };

    let url = format!("{}{}", cfg.service_url.trim_end_matches('/'), path);

    let req = client
        .post(&url)
        .headers(headers)
        .json(&payload)
        .build()
        .context("Failed to build request")?;

    let resp = client.execute(req).await.context("HTTP request failed")?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("KMS import failed: {}", body);
    }

    println!("Bootstrap import successful");

    Ok(())
}
