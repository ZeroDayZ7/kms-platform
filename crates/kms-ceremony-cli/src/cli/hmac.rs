use anyhow::{Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use uuid::Uuid;

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

pub fn canonical_request_string(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: Option<&str>,
    body_hash: Option<&str>,
) -> String {
    let nonce_part = nonce.map_or(String::new(), |n| format!(":{n}"));
    let body_part = body_hash.map_or(String::new(), |hash| format!(":{hash}"));
    format!("{method}:{path}:{timestamp}{nonce_part}{body_part}")
}

pub fn sign_hmac_sha256(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: Option<&str>,
    body_hash: Option<&str>,
) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC secret must be valid for SHA-256");
    mac.update(canonical_request_string(method, path, timestamp, nonce, body_hash).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn build_signed_request_headers_with_body(
    cfg: &CliConfig,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<HeaderMap> {
    let timestamp = Utc::now().timestamp();
    let nonce = Uuid::now_v7().to_string();
    let body_hash = body.map(sha256_hex);
    let signature = sign_hmac_sha256(
        &cfg.secret,
        method,
        path,
        timestamp,
        Some(&nonce),
        body_hash.as_deref(),
    );

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
        HeaderName::from_static("x-nonce"),
        HeaderValue::from_str(&nonce)?,
    );
    headers.insert(
        HeaderName::from_static("x-signature"),
        HeaderValue::from_str(&signature)?,
    );

    if let Some(hash) = body_hash.as_deref() {
        headers.insert(
            HeaderName::from_static("x-body-sha256"),
            HeaderValue::from_str(hash)?,
        );
        // When body is present, the request will have a JSON payload.
        // Ensure Content-Type is set so the server accepts the request.
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
    }

    Ok(headers)
}

pub fn build_signed_request_headers(
    cfg: &CliConfig,
    method: &str,
    path: &str,
) -> Result<HeaderMap> {
    build_signed_request_headers_with_body(cfg, method, path, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_string_includes_nonce_and_body_hash_for_mutating_requests() {
        let signature = sign_hmac_sha256(
            "secret",
            "POST",
            "/api/v1/test",
            1700000000,
            Some("n-123"),
            Some("abc123"),
        );

        assert_eq!(
            canonical_request_string(
                "POST",
                "/api/v1/test",
                1700000000,
                Some("n-123"),
                Some("abc123")
            ),
            "POST:/api/v1/test:1700000000:n-123:abc123"
        );
        assert!(!signature.is_empty());
    }

    #[test]
    fn body_hash_is_deterministic() {
        let body = br#"{"key":"value"}"#;
        assert_eq!(
            sha256_hex(body),
            "e43abcf3375244839c012f9633f95862d232a95b00d5bc7348b3098b9fed7f32"
        );
    }

    #[test]
    fn signed_headers_match_body_hash_for_post_requests() {
        let cfg = CliConfig {
            service_id: "kms-cli".to_string(),
            secret: "secret".to_string(),
            service_url: "http://localhost:8081".to_string(),
        };
        let body = br#"{"version":1,"target_resources":[],"credentials":[]}"#;

        let headers = build_signed_request_headers_with_body(
            &cfg,
            "POST",
            "/api/v1/admin/bootstrap/import",
            Some(body),
        )
        .expect("signed headers should be built");

        let timestamp = headers
            .get("x-timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .expect("x-timestamp header should exist");
        let nonce = headers
            .get("x-nonce")
            .and_then(|v| v.to_str().ok())
            .expect("x-nonce header should exist");
        let body_hash = headers
            .get("x-body-sha256")
            .and_then(|v| v.to_str().ok())
            .expect("x-body-sha256 header should exist");
        let signature = headers
            .get("x-signature")
            .and_then(|v| v.to_str().ok())
            .expect("x-signature header should exist");

        assert_eq!(body_hash, sha256_hex(body));
        assert_eq!(
            signature,
            sign_hmac_sha256(
                &cfg.secret,
                "POST",
                "/api/v1/admin/bootstrap/import",
                timestamp,
                Some(nonce),
                Some(body_hash)
            )
        );
    }
}
