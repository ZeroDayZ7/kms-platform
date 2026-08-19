use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    errors::{AppError, AppResult},
    hsm::protocol::{HsmRequest, HsmResponse},
};

const HSM_SOCKET_DEFAULT_PATH: &str = "/run/vhsm/vhsm.sock";

fn framed_message(payload: &[u8]) -> Result<Vec<u8>, AppError> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[cfg(unix)]
async fn read_frame(stream: &mut UnixStream) -> AppResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|err| {
        AppError::RuntimeError(format!("Failed to read HSM frame length: {err}"))
    })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.map_err(|err| {
        AppError::RuntimeError(format!("Failed to read HSM response payload: {err}"))
    })?;

    Ok(payload)
}

#[cfg(unix)]
pub async fn send_hsm_request(socket_path: &str, req: &HsmRequest) -> AppResult<HsmResponse> {
    let socket = socket_path.trim();
    let path = if socket.is_empty() {
        HSM_SOCKET_DEFAULT_PATH
    } else {
        socket
    };

    let mut stream = UnixStream::connect(path).await.map_err(|err| {
        AppError::RuntimeError(format!(
            "Failed to connect to HSM socket {}: {err}",
            path
        ))
    })?;

    let payload = serde_json::to_vec(req).map_err(AppError::SerializationError)?;
    let frame = framed_message(&payload)?;

    stream.write_all(&frame).await.map_err(|err| {
        AppError::RuntimeError(format!("Failed to write HSM request to {}: {err}", path))
    })?;

    let response_bytes = read_frame(&mut stream).await?;
    let response: HsmResponse = serde_json::from_slice(&response_bytes).map_err(AppError::SerializationError)?;

    match response {
        HsmResponse::Error { code, message } => Err(AppError::CryptoError(format!(
            "HSM returned error {code}: {message}"
        ))),
        _ => Ok(response),
    }
}

#[cfg(not(unix))]
pub async fn send_hsm_request(_socket_path: &str, _req: &HsmRequest) -> AppResult<HsmResponse> {
    Err(AppError::ConfigError(
        "Unix domain sockets are not available on this platform; HSM provider requires Unix sockets."
            .to_string(),
    ))
}

pub async fn encrypt_via_hsm(socket_path: &str, key_id: &str, plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let req = HsmRequest::Encrypt {
        key_id: key_id.to_string(),
        plaintext: plaintext.to_vec(),
    };

    match send_hsm_request(socket_path, &req).await? {
        HsmResponse::Encrypted { ciphertext } => Ok(ciphertext),
        HsmResponse::Error { code, message } => Err(AppError::CryptoError(format!(
            "HSM encryption failed ({code}): {message}"
        ))),
        other => Err(AppError::CryptoError(format!(
            "Unexpected HSM response for encrypt: {other:?}"
        ))),
    }
}

pub async fn decrypt_via_hsm(socket_path: &str, key_id: &str, ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    let req = HsmRequest::Decrypt {
        key_id: key_id.to_string(),
        ciphertext: ciphertext.to_vec(),
    };

    match send_hsm_request(socket_path, &req).await? {
        HsmResponse::Decrypted { plaintext } => Ok(plaintext),
        HsmResponse::Error { code, message } => Err(AppError::CryptoError(format!(
            "HSM decryption failed ({code}): {message}"
        ))),
        other => Err(AppError::CryptoError(format!(
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
}
