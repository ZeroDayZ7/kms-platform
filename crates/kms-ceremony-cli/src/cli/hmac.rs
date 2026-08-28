use anyhow::{Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub service_id: String,
    pub secret: String,
    pub service_url: String,
}

pub fn resolve_cli_config(service_url: Option<String>) -> Result<CliConfig> {
    let service_id = std::env::var("KMS_CLI__SERVICE_ID").unwrap_or_else(|_| "kms-cli".to_string());
    let secret = std::env::var("KMS_CLI__SECRET")
        .context("KMS_CLI__SECRET is required for authenticated HTTP calls")?;
    let service_url = service_url
        .or_else(|| std::env::var("KMS_CLI__SERVICE_URL").ok())
        .unwrap_or_else(|| "http://localhost:8081".to_string());

    Ok(CliConfig {
        service_id,
        secret,
        service_url,
    })
}

pub fn canonical_request_string(method: &str, path: &str, timestamp: i64) -> String {
    format!("{method}:{path}:{timestamp}")
}

pub fn sign_hmac_sha256(secret: &str, method: &str, path: &str, timestamp: i64) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC secret must be valid for SHA-256");
    mac.update(canonical_request_string(method, path, timestamp).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn build_signed_request_headers(
    cfg: &CliConfig,
    method: &str,
    path: &str,
) -> Result<HeaderMap> {
    let timestamp = Utc::now().timestamp();
    let signature = sign_hmac_sha256(&cfg.secret, method, path, timestamp);

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-service-id"),
        HeaderValue::from_str(&cfg.service_id)?,
    );
    headers.insert(
        HeaderName::from_static("x-timestamp"),
        HeaderValue::from_str(&timestamp.to_string())?,
    );
    headers.insert(
        HeaderName::from_static("x-signature"),
        HeaderValue::from_str(&signature)?,
    );
    Ok(headers)
}
