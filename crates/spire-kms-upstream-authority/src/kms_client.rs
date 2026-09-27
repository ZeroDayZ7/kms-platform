use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;

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
#[cfg(unix)]
pub async fn sign_csr_via_kms(
    socket_path: &str,
    req: KmsSignRequest,
) -> anyhow::Result<KmsSignResponse> {
    if !Path::new(socket_path).exists() {
        anyhow::bail!("KMS socket not available at {}", socket_path);
    }

    let mut stream = UnixStream::connect(socket_path).await?;
    let payload = serde_json::to_vec(&req)?;
    let len = payload.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;

    let mut len_buf = [0_u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0_u8; response_len];
    stream.read_exact(&mut response_buf).await?;

    let response: KmsSignResponse = serde_json::from_slice(&response_buf)?;
    Ok(response)
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
