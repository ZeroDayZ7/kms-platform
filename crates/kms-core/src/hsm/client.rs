use crate::hsm::protocol::{HsmRequest, HsmResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmClientError {
    #[error("connection to HSM failed")]
    Io {
        #[source]
        source: std::io::Error,
    },
    #[error("HSM request timed out")]
    Timeout,
    #[error("HSM frame is invalid")]
    InvalidFrame,
    #[error("HSM response was invalid")]
    InvalidResponse,
    #[error("serializing HSM request failed")]
    Serialization {
        #[source]
        source: serde_json::Error,
    },
    #[error("HSM returned an error: {0}")]
    Remote(String),
    #[error("Unix domain sockets are not available on this platform")]
    PlatformNotSupported,
}

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
//#region framed_message
pub fn framed_message(payload: &[u8]) -> HsmResult<Vec<u8>> {
    if payload.len() > MAX_HSM_FRAME_SIZE {
        return Err(HsmClientError::InvalidFrame);
    }

    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| HsmClientError::InvalidFrame)?;
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
    .map_err(|_| HsmClientError::Timeout)?
    .map_err(|err| HsmClientError::Io { source: err })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HSM_FRAME_SIZE {
        return Err(HsmClientError::InvalidFrame);
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut payload),
    )
    .await
    .map_err(|_| HsmClientError::Timeout)?
    .map_err(|err| HsmClientError::Io { source: err })?;

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
            .map_err(|_| HsmClientError::Timeout)?
            .map_err(|err| HsmClientError::Io { source: err })?;

    let payload =
        serde_json::to_vec(req).map_err(|err| HsmClientError::Serialization { source: err })?;
    let frame = framed_message(&payload)?;

    tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(&frame))
        .await
        .map_err(|_| HsmClientError::Timeout)?
        .map_err(|err| HsmClientError::Io { source: err })?;

    let response_bytes = read_frame(&mut stream).await?;
    let response: HsmResponse = serde_json::from_slice(&response_bytes)
        .map_err(|err| HsmClientError::Serialization { source: err })?;

    match response {
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
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
        HsmResponse::Encrypted {
            ciphertext,
            key_version,
        } => {
            if key_version == 0 {
                return Err(HsmClientError::InvalidResponse);
            }
            Ok(ciphertext)
        }
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "HSM encryption failed ({code}): {message}"
        ))),
        _other => Err(HsmClientError::InvalidResponse),
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
        HsmResponse::Decrypted {
            plaintext,
            key_version,
        } => {
            if key_version == 0 {
                return Err(HsmClientError::InvalidResponse);
            }
            Ok(plaintext)
        }
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "HSM decryption failed ({code}): {message}"
        ))),
        _other => Err(HsmClientError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //#region framed_message_has_length_prefix
    fn framed_message_has_length_prefix() {
        let msg = framed_message(b"abc").unwrap();
        assert_eq!(msg.len(), 7);
        assert_eq!(&msg[..4], &[0, 0, 0, 3]);
        assert_eq!(&msg[4..], b"abc");
    }

    #[test]
    //#region framed_message_rejects_payloads_above_limit
    fn framed_message_rejects_payloads_above_limit() {
        let oversized = vec![0u8; MAX_HSM_FRAME_SIZE + 1];
        let err = framed_message(&oversized).unwrap_err();
        assert!(matches!(err, HsmClientError::InvalidFrame));
    }
}
