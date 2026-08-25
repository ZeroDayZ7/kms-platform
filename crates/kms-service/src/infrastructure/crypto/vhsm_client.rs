use crate::errors::{AppError, AppResult};
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

#[derive(Clone)]
#[allow(dead_code)]
pub struct VhsmClient {
    socket_path: String,
}

impl VhsmClient {
    //#region new
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    #[cfg(unix)]
    async fn send_request(&self, request: &HsmRequest) -> AppResult<HsmResponse> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let payload =
            serde_json::to_vec(request).map_err(|e| AppError::SerializationError(e.to_string()))?;

        let len_header = (payload.len() as u32).to_be_bytes();

        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            AppError::RuntimeError(format!(
                "Nie udało się połączyć z vhsm-daemon pod ścieżką {}: {e}",
                self.socket_path
            ))
        })?;

        stream
            .write_all(&len_header)
            .await
            .map_err(|e| AppError::RuntimeError(format!("Błąd zapisu nagłówka do vHSM: {e}")))?;

        stream
            .write_all(&payload)
            .await
            .map_err(|e| AppError::RuntimeError(format!("Błąd zapisu ładunku do vHSM: {e}")))?;

        let mut header_buf = [0u8; 4];
        stream.read_exact(&mut header_buf).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd odczytu nagłówka odpowiedzi z vHSM: {e}"))
        })?;

        let response_len = u32::from_be_bytes(header_buf) as usize;
        let mut response_buf = vec![0u8; response_len];

        stream.read_exact(&mut response_buf).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd odczytu treści odpowiedzi z vHSM: {e}"))
        })?;

        let response: HsmResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        Ok(response)
    }

    #[cfg(not(unix))]
    async fn send_request(&self, _request: &HsmRequest) -> AppResult<HsmResponse> {
        Err(AppError::RuntimeError(
            "vHSM Unix Domain Sockets są wspierane wyłącznie na systemach Unix/Linux.".to_string(),
        ))
    }

    pub async fn status(&self) -> AppResult<u32> {
        let req = HsmRequest::Status;
        match self.send_request(&req).await? {
            HsmResponse::StatusInfo { active_key_version, .. } => Ok(active_key_version),
            HsmResponse::Error { message, .. } => {
                Err(AppError::CryptoError(format!("vHSM status error: {message}")))
            }
            _ => Err(AppError::CryptoError("Nieoczekiwana odpowiedź vHSM dla status".into())),
        }
    }

    pub async fn is_ready(&self) -> bool {
        let req = HsmRequest::Status;
        match self.send_request(&req).await {
            Ok(HsmResponse::StatusInfo { initialized, .. }) => initialized,
            _ => false,
        }
    }

    pub async fn encrypt(&self, plaintext: &[u8]) -> AppResult<Vec<u8>> {
        let req = HsmRequest::Encrypt {
            key_id: "master_key".to_string(),
            key_version: None,
            plaintext: plaintext.to_vec(),
        };

        match self.send_request(&req).await? {
            HsmResponse::Encrypted { ciphertext } => Ok(ciphertext),
            HsmResponse::Error { message, .. } => {
                Err(AppError::CryptoError(format!("vHSM błąd: {message}")))
            }
            _ => Err(AppError::CryptoError("Nieoczekiwana odpowiedź vHSM".into())),
        }
    }

    pub async fn decrypt(&self, ciphertext: &[u8]) -> AppResult<Vec<u8>> {
        let req = HsmRequest::Decrypt {
            key_id: "master_key".to_string(),
            key_version: None,
            ciphertext: ciphertext.to_vec(),
        };

        match self.send_request(&req).await? {
            HsmResponse::Decrypted { plaintext } => Ok(plaintext),
            HsmResponse::Error { message, .. } => {
                Err(AppError::CryptoError(format!("vHSM błąd: {message}")))
            }
            _ => Err(AppError::CryptoError("Nieoczekiwana odpowiedź vHSM".into())),
        }
    }
}
