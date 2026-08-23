// crates/kms-core/src/hsm/client.rs
use crate::hsm::protocol::{HsmRequest, HsmResponse};
use std::fmt;

#[derive(Debug)]
pub enum HsmClientError {
    IoError(String),
    SerializationError(String),
    CryptoError(String),
    PlatformNotSupported,
}

impl fmt::Display for HsmClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsmClientError::IoError(e) => write!(f, "HSM I/O error: {e}"),
            HsmClientError::SerializationError(e) => write!(f, "HSM serialization error: {e}"),
            HsmClientError::CryptoError(e) => write!(f, "HSM crypto error: {e}"),
            HsmClientError::PlatformNotSupported => write!(
                f,
                "Unix domain sockets are not available on this platform; HSM provider requires Unix sockets."
            ),
        }
    }
}

impl std::error::Error for HsmClientError {}

pub type HsmResult<T> = Result<T, HsmClientError>;

#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub const HSM_SOCKET_DEFAULT_PATH: &str = "/run/vhsm/vhsm.sock";

#[cfg(any(unix, test))]
const MAX_HSM_FRAME_SIZE: usize = 1024 * 1024; // 1 MiB, fail-closed

#[cfg(any(unix, test))]
pub fn framed_message(payload: &[u8]) -> HsmResult<Vec<u8>> {
    if payload.len() > MAX_HSM_FRAME_SIZE {
        return Err(HsmClientError::IoError(format!(
            "HSM payload exceeds maximum allowed size of {MAX_HSM_FRAME_SIZE} bytes"
        )));
    }

    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| HsmClientError::IoError("HSM payload length overflow".to_string()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[cfg(unix)]
async fn read_frame(stream: &mut UnixStream) -> HsmResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| HsmClientError::IoError("Timed out while reading HSM frame length".to_string()))??
    .map_err(|err| HsmClientError::IoError(format!("Failed to read HSM frame length: {err}")))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HSM_FRAME_SIZE {
        return Err(HsmClientError::IoError(format!(
            "HSM frame exceeds maximum allowed size of {MAX_HSM_FRAME_SIZE} bytes"
        )));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut payload),
    )
    .await
    .map_err(|_| {
        HsmClientError::IoError("Timed out while reading HSM response payload".to_string())
    })??
    .map_err(|err| {
        HsmClientError::IoError(format!("Failed to read HSM response payload: {err}"))
    })?;

    Ok(payload)
}

#[cfg(unix)]
pub async fn send_hsm_request(socket_path: &str, req: &HsmRequest) -> HsmResult<HsmResponse> {
    let socket = socket_path.trim();
    let path = if socket.is_empty() {
        HSM_SOCKET_DEFAULT_PATH
    } else {
        socket
    };

    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(5), UnixStream::connect(path))
            .await
            .map_err(|_| {
                HsmClientError::IoError(format!("Timed out while connecting to HSM socket {path}"))
            })??
            .map_err(|err| {
                HsmClientError::IoError(format!("Failed to connect to HSM socket {path}: {err}"))
            })?;

    let payload =
        serde_json::to_vec(req).map_err(|e| HsmClientError::SerializationError(e.to_string()))?;
    let frame = framed_message(&payload)?;

    tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(&frame))
        .await
        .map_err(|_| {
            HsmClientError::IoError(format!("Timed out while writing HSM request to {path}"))
        })??
        .map_err(|err| {
            HsmClientError::IoError(format!("Failed to write HSM request to {path}: {err}"))
        })?;

    let response_bytes = read_frame(&mut stream).await?;
    let response: HsmResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| HsmClientError::SerializationError(e.to_string()))?;

    match response {
        HsmResponse::Error { code, message } => Err(HsmClientError::CryptoError(format!(
            "HSM returned error {code}: {message}"
        ))),
        _ => Ok(response),
    }
}

#[cfg(not(unix))]
pub async fn send_hsm_request(_socket_path: &str, _req: &HsmRequest) -> HsmResult<HsmResponse> {
    Err(HsmClientError::PlatformNotSupported)
}

pub async fn encrypt_via_hsm(
    socket_path: &str,
    key_id: &str,
    key_version: Option<u32>,
    plaintext: &[u8],
) -> HsmResult<Vec<u8>> {
    let req = HsmRequest::Encrypt {
        key_id: key_id.to_string(),
        key_version,
        plaintext: plaintext.to_vec(),
    };

    match send_hsm_request(socket_path, &req).await? {
        HsmResponse::Encrypted { ciphertext } => Ok(ciphertext),
        HsmResponse::Error { code, message } => Err(HsmClientError::CryptoError(format!(
            "HSM encryption failed ({code}): {message}"
        ))),
        other => Err(HsmClientError::CryptoError(format!(
            "Unexpected HSM response for encrypt: {other:?}"
        ))),
    }
}

pub async fn decrypt_via_hsm(
    socket_path: &str,
    key_id: &str,
    key_version: Option<u32>,
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    let req = HsmRequest::Decrypt {
        key_id: key_id.to_string(),
        key_version,
        ciphertext: ciphertext.to_vec(),
    };

    match send_hsm_request(socket_path, &req).await? {
        HsmResponse::Decrypted { plaintext } => Ok(plaintext),
        HsmResponse::Error { code, message } => Err(HsmClientError::CryptoError(format!(
            "HSM decryption failed ({code}): {message}"
        ))),
        other => Err(HsmClientError::CryptoError(format!(
            "Unexpected HSM response for decrypt: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_message_has_length_prefix() {
        let msg = framed_message(b"abc").unwrap();
        assert_eq!(msg.len(), 7);
        assert_eq!(&msg[..4], &[0, 0, 0, 3]);
        assert_eq!(&msg[4..], b"abc");
    }

    #[test]
    fn framed_message_rejects_payloads_above_limit() {
        let oversized = vec![0u8; MAX_HSM_FRAME_SIZE + 1];
        let err = framed_message(&oversized).unwrap_err();
        assert!(format!("{err}").contains("maximum allowed size"));
    }
}
