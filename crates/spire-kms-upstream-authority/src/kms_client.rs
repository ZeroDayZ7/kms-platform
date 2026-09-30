use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::path::Path;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{TcpStream, UnixStream};

#[allow(dead_code)]
const MAX_KMS_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
// Keep a conservative but reasonable default timeout for KMS RPCs
#[allow(dead_code)]
const KMS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsSignRequest {
    pub csr_pem: String,
    pub ca_tag: String,
    pub validity_days: u32,
    pub caller_service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsSignResponse {
    pub certificate_pem: String,
    pub root_certificate_pem: Option<String>,
}

#[cfg(unix)]
pub async fn sign_csr_via_kms(
    socket_path: &str,
    req: KmsSignRequest,
) -> anyhow::Result<KmsSignResponse> {
    // Allow addresses like `unix:/run/kms/kms.sock` or `tcp:127.0.0.1:8080`.
    let (is_tcp, path) = if socket_path.starts_with("tcp:") {
        (true, socket_path.trim_start_matches("tcp:").to_string())
    } else if socket_path.starts_with("unix:") {
        (false, socket_path.trim_start_matches("unix:").to_string())
    } else {
        (false, socket_path.to_string())
    };

    if !is_tcp && !Path::new(&path).exists() {
        anyhow::bail!("KMS socket not available at {}", path);
    }

    const ATTEMPTS: usize = 5;
    const INITIAL_BACKOFF_MS: u64 = 500;

    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=ATTEMPTS {
        let attempt_desc = format!("{}/{}", attempt, ATTEMPTS);

        let fut = async {
            // encapsulate the request/response exchange so we can reuse for both stream types
            let payload = serde_json::to_vec(&req)?;
            let len = payload.len() as u32;

            if is_tcp {
                let mut stream = TcpStream::connect(&path).await?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&payload).await?;
                stream.flush().await?;

                let mut len_buf = [0_u8; 4];
                stream.read_exact(&mut len_buf).await?;
                let response_len = u32::from_be_bytes(len_buf) as usize;

                if response_len > MAX_KMS_RESPONSE_SIZE {
                    anyhow::bail!(
                        "KMS response length {} exceeds limit {}",
                        response_len,
                        MAX_KMS_RESPONSE_SIZE
                    );
                }

                let mut response_buf = vec![0_u8; response_len];
                let mut read = 0usize;
                while read < response_len {
                    let n = stream.read(&mut response_buf[read..]).await?;
                    if n == 0 {
                        anyhow::bail!("unexpected EOF while reading KMS response")
                    }
                    read += n;
                }

                // First parse as generic JSON to detect HSM error responses
                let v: serde_json::Value = serde_json::from_slice(&response_buf)?;
                if let Some(err_obj) = v.get("Error") {
                    let code = err_obj.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                    let message = err_obj
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    anyhow::bail!("KMS error {}: {}", code, message);
                }

                if let Some(signed) = v.get("SignedIntermediate") {
                    let cert = signed
                        .get("certificate_pem")
                        .and_then(|c| c.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!("missing certificate_pem in SignedIntermediate")
                        })?;
                    return Ok::<KmsSignResponse, anyhow::Error>(KmsSignResponse {
                        certificate_pem: cert.to_string(),
                        root_certificate_pem: None,
                    });
                }

                // Fallback: try to deserialize into expected success DTO
                let response: KmsSignResponse = serde_json::from_slice(&response_buf)?;
                Ok::<KmsSignResponse, anyhow::Error>(response)
            } else {
                let mut stream = UnixStream::connect(&path).await?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&payload).await?;
                stream.flush().await?;

                let mut len_buf = [0_u8; 4];
                stream.read_exact(&mut len_buf).await?;
                let response_len = u32::from_be_bytes(len_buf) as usize;

                if response_len > MAX_KMS_RESPONSE_SIZE {
                    anyhow::bail!(
                        "KMS response length {} exceeds limit {}",
                        response_len,
                        MAX_KMS_RESPONSE_SIZE
                    );
                }

                let mut response_buf = vec![0_u8; response_len];
                let mut read = 0usize;
                while read < response_len {
                    let n = stream.read(&mut response_buf[read..]).await?;
                    if n == 0 {
                        anyhow::bail!("unexpected EOF while reading KMS response")
                    }
                    read += n;
                }

                // First parse as generic JSON to detect HSM error responses
                let v: serde_json::Value = serde_json::from_slice(&response_buf)?;
                if let Some(err_obj) = v.get("Error") {
                    let code = err_obj.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                    let message = err_obj
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    anyhow::bail!("KMS error {}: {}", code, message);
                }

                if let Some(signed) = v.get("SignedIntermediate") {
                    let cert = signed
                        .get("certificate_pem")
                        .and_then(|c| c.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!("missing certificate_pem in SignedIntermediate")
                        })?;
                    return Ok::<KmsSignResponse, anyhow::Error>(KmsSignResponse {
                        certificate_pem: cert.to_string(),
                        root_certificate_pem: None,
                    });
                }

                // Fallback: try to deserialize into expected success DTO
                let response: KmsSignResponse = serde_json::from_slice(&response_buf)?;
                Ok::<KmsSignResponse, anyhow::Error>(response)
            }
        };

        match tokio::time::timeout(KMS_TIMEOUT, fut).await {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, attempt = %attempt_desc, "KMS request failed");
                last_err = Some(e);
            }
            Err(_) => {
                let to_err = anyhow::anyhow!("KMS request timed out after {:?}", KMS_TIMEOUT);
                tracing::warn!(error = %to_err, attempt = %attempt_desc, "KMS request timed out");
                last_err = Some(to_err);
            }
        }

        // exponential backoff
        if attempt < ATTEMPTS {
            let backoff_ms = INITIAL_BACKOFF_MS.saturating_mul(1u64 << (attempt - 1));
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("KMS request failed")))
}

#[cfg(not(unix))]
pub async fn sign_csr_via_kms(
    _socket_path: &str,
    _req: KmsSignRequest,
) -> anyhow::Result<KmsSignResponse> {
    anyhow::bail!(
        "Unix Domain Socket KMS client is only supported on Unix-like systems; this host is {}",
        std::env::consts::OS
    )
}

#[cfg(test)]
mod tests {
    use super::KmsSignRequest;

    #[test]
    fn sign_request_serializes() {
        let req = KmsSignRequest {
            csr_pem: "test-csr".to_string(),
            ca_tag: "root".to_string(),
            validity_days: 365,
            caller_service: "spire".to_string(),
        };

        let json = serde_json::to_string(&req).expect("serializes");
        assert!(json.contains("spire"));
        assert!(json.contains("root"));
    }
}
