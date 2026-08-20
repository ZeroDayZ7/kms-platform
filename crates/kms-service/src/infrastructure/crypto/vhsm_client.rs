use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use serde::{Deserialize, Serialize};
use crate::errors::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum VhsmCommand {
    Encrypt { plaintext: String },
    Decrypt { ciphertext: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VhsmResponse {
    Success { data: String },
    Error { message: String },
}

#[derive(Clone)]
pub struct VhsmClient {
    socket_path: String,
}

impl VhsmClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    async fn send_request(&self, command: &VhsmCommand) -> AppResult<String> {
        let payload = serde_json::to_vec(command)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        let len_header = (payload.len() as u32).to_be_bytes();

        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            AppError::RuntimeError(format!("Nie udało się połączyć z vhsm-daemon pod ścieżką {}: {e}", self.socket_path))
        });

        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        stream.write_all(&len_header).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd zapisu nagłówka do vHSM: {e}"))
        })?;

        stream.write_all(&payload).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd zapisu ładunku do vHSM: {e}"))
        })?;

        let mut header_buf = [0u8; 4];
        stream.read_exact(&mut header_buf).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd odczytu nagłówka odpowiedzi z vHSM: {e}"))
        })?;

        let response_len = u32::from_be_bytes(header_buf) as usize;
        let mut response_buf = vec![0u8; response_len];
        
        stream.read_exact(&mut response_buf).await.map_err(|e| {
            AppError::RuntimeError(format!("Błąd odczytu treści odpowiedzi z vHSM: {e}"))
        })?;

        let response: VhsmResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        match response {
            VhsmResponse::Success { data } => Ok(data),
            VhsmResponse::Error { message } => Err(AppError::CryptoError(format!(
                "vHSM zwrócił błąd: {message}"
            ))),
        }
    }

    pub async fn encrypt(&self, plaintext_hex: &str) -> AppResult<String> {
        self.send_request(&VhsmCommand::Encrypt {
            plaintext: plaintext_hex.to_string(),
        }).await
    }

    pub async fn decrypt(&self, ciphertext_hex: &str) -> AppResult<String> {
        self.send_request(&VhsmCommand::Decrypt {
            ciphertext: ciphertext_hex.to_string(),
        }).await
    }
}