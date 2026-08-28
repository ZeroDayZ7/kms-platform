use anyhow::{Context, Result};
use reqwest::Url;
use std::path::PathBuf;

use crate::cli::hmac::{build_signed_request_headers, resolve_cli_config};

#[derive(serde::Deserialize)]
struct VerifyReport {
    ok: bool,
    ok_count: usize,
    errors: Vec<String>,
}

pub async fn handle_verify_audit(
    service_url: Option<String>,
    _vhsmpub: Option<PathBuf>,
    limit: Option<usize>,
    full: bool,
) -> Result<()> {
    let cfg = resolve_cli_config(service_url)?;

    let mut url = Url::parse(&cfg.service_url).context("Invalid service URL")?;
    url.set_path("/api/v1/audit/verify");

    {
        let mut qp = url.query_pairs_mut();
        if let Some(n) = limit {
            qp.append_pair("limit", &n.to_string());
        }
        if full {
            qp.append_pair("full", "true");
        }
    }

    let client = reqwest::Client::new();
    let request = client.get(url).headers(build_signed_request_headers(
        &cfg,
        "GET",
        "/api/v1/audit/verify",
    )?);
    let resp = request.send().await?;
    let status = resp.status();

    if status.is_success() {
        let rpt: VerifyReport = resp
            .json()
            .await
            .context("Failed to parse JSON response from service")?;

        if rpt.ok {
            println!("✅ Audit chain verified: {} records OK", rpt.ok_count);
            Ok(())
        } else {
            eprintln!("❌ Audit chain verification failed: {:?}", rpt.errors);
            anyhow::bail!("Audit chain verification failed")
        }
    } else {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Service returned {}: {}", status, text)
    }
}
