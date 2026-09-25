//crates/kms-core/src/hsm/client.rs

use crate::hsm::protocol::{HsmRequest, HsmResponse};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

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
async fn read_frame_with_timeout(stream: &mut UnixStream, timeout: Duration) -> HsmResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| HsmClientError::Timeout)?
        .map_err(|err| HsmClientError::Io { source: err })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HSM_FRAME_SIZE {
        return Err(HsmClientError::InvalidFrame);
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload))
        .await
        .map_err(|_| HsmClientError::Timeout)?
        .map_err(|err| HsmClientError::Io { source: err })?;

    Ok(payload)
}

#[cfg(unix)]
pub async fn send_hsm_request(
    socket_path: &str,
    req: &HsmRequest,
    timeout: Option<Duration>,
) -> HsmResult<HsmResponse> {
    let timeout = timeout.unwrap_or_else(|| Duration::from_secs(5));

    let socket = socket_path.trim();
    let path = if socket.is_empty() {
        HSM_SOCKET_DEFAULT_PATH
    } else {
        socket
    };

    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(path))
        .await
        .map_err(|_| HsmClientError::Timeout)?
        .map_err(|err| HsmClientError::Io { source: err })?;

    let payload =
        serde_json::to_vec(req).map_err(|err| HsmClientError::Serialization { source: err })?;

    // Ensure the serialized payload is zeroized after use
    let payload_z = Zeroizing::new(payload);
    let frame = framed_message(&*payload_z)?;

    // Zeroize the frame after writing
    let frame_z = Zeroizing::new(frame);
    tokio::time::timeout(timeout, stream.write_all(&*frame_z))
        .await
        .map_err(|_| HsmClientError::Timeout)?
        .map_err(|err| HsmClientError::Io { source: err })?;

    let response_bytes = read_frame_with_timeout(&mut stream, timeout).await?;

    // Zeroize raw response bytes after deserialization
    let response_z = Zeroizing::new(response_bytes);
    let response: HsmResponse = serde_json::from_slice(&*response_z)
        .map_err(|err| HsmClientError::Serialization { source: err })?;

    match response {
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "HSM returned error {code}: {message}"
        ))),
        _ => Ok(response),
    }
}

#[cfg(not(unix))]
pub async fn send_hsm_request(
    _socket_path: &str,
    _req: &HsmRequest,
    _timeout: Option<Duration>,
) -> HsmResult<HsmResponse> {
    Err(HsmClientError::PlatformNotSupported)
}

pub async fn encrypt_via_hsm(
    socket_path: &str,
    key_id: &str,
    key_version: Option<u32>,
    plaintext: &[u8],
    timeout: Option<Duration>,
) -> HsmResult<Vec<u8>> {
    let requested = key_version;
    let req = HsmRequest::Encrypt {
        key_id: key_id.to_string(),
        key_version,
        plaintext: plaintext.to_vec(),
    };

    match send_hsm_request(socket_path, &req, timeout).await? {
        HsmResponse::Encrypted {
            ciphertext,
            key_version: resp_version,
        } => {
            // Validate returned key version against requested version to prevent downgrade
            validate_key_version(requested, resp_version)?;
            if resp_version == 0 {
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
    timeout: Option<Duration>,
) -> HsmResult<Vec<u8>> {
    let requested = key_version;
    let req = HsmRequest::Decrypt {
        key_id: key_id.to_string(),
        key_version,
        ciphertext: ciphertext.to_vec(),
    };

    match send_hsm_request(socket_path, &req, timeout).await? {
        HsmResponse::Decrypted {
            plaintext,
            key_version: resp_version,
        } => {
            // Validate returned key version against requested version to prevent downgrade
            validate_key_version(requested, resp_version)?;
            if resp_version == 0 {
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

/// Load an encrypted root CA blob into vHSM memory. Returns Ok(()) on success.
pub async fn load_root_ca_via_hsm(
    socket_path: &str,
    ca_tag: &str,
    encrypted_private_key: &[u8],
    timeout: Option<Duration>,
) -> HsmResult<()> {
    let req = HsmRequest::LoadRootCa {
        ca_tag: ca_tag.to_string(),
        encrypted_private_key: encrypted_private_key.to_vec(),
    };

    match send_hsm_request(socket_path, &req, timeout).await? {
        HsmResponse::MasterKeyInitialized => Ok(()),
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "vHSM load Root CA failed ({code}): {message}"
        ))),
        _ => Err(HsmClientError::InvalidResponse),
    }
}

//#region generate_random_bytes_via_hsm
/// Wywołuje vHSM przez UDS w celu wygenerowania bezpiecznych losowych bajtów (entropii/poświadczenia).
pub async fn generate_random_bytes_via_hsm(
    socket_path: &str,
    length: usize,
    timeout: Option<Duration>,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    let req = HsmRequest::GenerateRandomBytes { length };

    match send_hsm_request(socket_path, &req, timeout).await? {
        HsmResponse::RandomBytesGenerated { random_bytes } => {
            if random_bytes.len() != length {
                return Err(HsmClientError::InvalidResponse);
            }
            Ok(Zeroizing::new(random_bytes))
        }
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "HSM random bytes generation failed ({code}): {message}"
        ))),
        _other => Err(HsmClientError::InvalidResponse),
    }
}

pub async fn generate_root_ca_via_hsm(
    socket_path: &str,
    algorithm: &str,
    timeout: Option<Duration>,
) -> HsmResult<(Vec<u8>, Vec<u8>, u32, String)> {
    let req = HsmRequest::InitRootCa {
        ca_tag: "root".to_string(),
        common_name: "kms-root-ca".to_string(),
        validity_days: 365 * 20,
        algorithm: algorithm.to_string(),
    };

    match send_hsm_request(socket_path, &req, timeout).await? {
        HsmResponse::RootCaKeyGenerated {
            encrypted_private_key,
            public_key,
            master_key_version,
            algorithm,
        } => Ok((
            encrypted_private_key,
            public_key,
            master_key_version,
            algorithm,
        )),
        HsmResponse::Error { code, message } => Err(HsmClientError::Remote(format!(
            "vHSM InitRootCa failed ({code}): {message}"
        ))),
        _ => Err(HsmClientError::InvalidResponse),
    }
}

// Helper to validate key version consistency and detect downgrade attacks.
fn validate_key_version(requested: Option<u32>, response_version: u32) -> HsmResult<()> {
    if let Some(req_v) = requested {
        if response_version < req_v {
            return Err(HsmClientError::Remote(format!(
                "Downgrade detected: response version {} < requested {}",
                response_version, req_v
            )));
        }
        if response_version != req_v {
            return Err(HsmClientError::InvalidResponse);
        }
    }
    Ok(())
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

    #[test]
    fn validate_key_version_accepts_none() {
        assert!(validate_key_version(None, 1).is_ok());
    }

    #[test]
    fn validate_key_version_rejects_downgrade() {
        let res = validate_key_version(Some(5), 4);
        assert!(res.is_err());
    }

    #[test]
    fn validate_key_version_rejects_mismatch() {
        let res = validate_key_version(Some(3), 4);
        assert!(res.is_err());
    }
}
