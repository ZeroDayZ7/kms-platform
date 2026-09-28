use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use kms_core::hsm::client::load_root_ca_via_hsm;

pub async fn handle_ca_load(
    socket_path: String,
    ca_tag: String,
    encrypted_b64: Option<String>,
    service_url: Option<String>,
    service_id: Option<String>,
    secret: Option<String>,
) -> Result<()> {
    // If encrypted_b64 is provided, perform a local load and notify the service with the blob.
    if let Some(b64) = encrypted_b64 {
        let encrypted = BASE64_ENGINE.decode(&b64)?;
        load_root_ca_via_hsm(&socket_path, &ca_tag, &encrypted, None).await?;

        let manifest = serde_json::json!({
            "operation": "ca_load",
            "ca_tag": ca_tag,
            "encrypted_private_key_b64": BASE64_ENGINE.encode(&encrypted),
        });

        let cfg = crate::cli::hmac::CliConfig {
            service_id: service_id
                .or_else(|| std::env::var("KMS_CLI__SERVICE_ID").ok())
                .unwrap_or_else(|| "kms-cli".to_string()),
            secret: secret
                .or_else(|| std::env::var("KMS_CLI__SECRET").ok())
                .expect("KMS_CLI__SECRET required for authenticated calls"),
            service_url: service_url
                .or_else(|| std::env::var("KMS_CLI__SERVICE_URL").ok())
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
        };

        let client = reqwest::Client::new();
        let path = "/api/v1/ca/load";
        let body = serde_json::to_vec(&manifest)?;
        let headers = crate::cli::hmac::build_signed_request_headers_with_body(
            &cfg,
            "POST",
            path,
            Some(&body),
        )?;
        let url = format!("{}{}", cfg.service_url.trim_end_matches('/'), path);
        let req = client.post(&url).headers(headers).body(body).build()?;
        let resp = client.execute(req).await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "kms-service returned error: {}",
                resp.text().await.unwrap_or_default()
            )
        }
    } else {
        // No blob provided: ask KMS service to fetch blob from DB and load it into vHSM.
        let cfg = crate::cli::hmac::CliConfig {
            service_id: service_id
                .or_else(|| std::env::var("KMS_CLI__SERVICE_ID").ok())
                .unwrap_or_else(|| "kms-cli".to_string()),
            secret: secret
                .or_else(|| std::env::var("KMS_CLI__SECRET").ok())
                .expect("KMS_CLI__SECRET required for authenticated calls"),
            service_url: service_url
                .or_else(|| std::env::var("KMS_CLI__SERVICE_URL").ok())
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
        };

        let client = reqwest::Client::new();
        let path = "/api/v1/ca/load";
        let manifest = serde_json::json!({"operation": "ca_load", "ca_tag": ca_tag});
        let body = serde_json::to_vec(&manifest)?;
        let headers = crate::cli::hmac::build_signed_request_headers_with_body(
            &cfg,
            "POST",
            path,
            Some(&body),
        )?;
        let url = format!("{}{}", cfg.service_url.trim_end_matches('/'), path);
        let req = client.post(&url).headers(headers).body(body).build()?;
        let resp = client.execute(req).await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "kms-service returned error: {}",
                resp.text().await.unwrap_or_default()
            )
        }
    }

    println!("CA '{}' loaded into vHSM", ca_tag);
    Ok(())
}
