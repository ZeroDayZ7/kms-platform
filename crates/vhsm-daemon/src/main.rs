use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum VhsmRequest {
    /// Komenda wywoływana przez CLI podczas uruchomienia / ceremonii
    InitMasterKey { master_key_hex: String },
    /// Operacja szyfrowania dla kms-service
    Encrypt { plaintext: Vec<u8> },
    /// Operacja odszyfrowania dla kms-service
    Decrypt { nonce: Vec<u8>, ciphertext: Vec<u8> },
    /// Zapytanie o stan vHSM
    Status,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum VhsmResponse {
    InitSuccess,
    StatusResponse { is_unlocked: bool },
    EncryptSuccess { nonce: Vec<u8>, ciphertext: Vec<u8> },
    DecryptSuccess { plaintext: Vec<u8> },
    Error { error: String },
}

/// Stan wewnętrzny demona w pamięci RAM
pub struct VhsmState {
    pub cipher: Option<Aes256Gcm>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon w trybie zero-trust...");

    // Stan startowy: vHSM jest ZABLOKOWANY (brak klucza w pamięci RAM)
    let state = Arc::new(RwLock::new(VhsmState { cipher: None }));

    #[cfg(unix)]
    {
        run_unix_listener(state).await?;
    }

    #[cfg(not(unix))]
    {
        let _ = state;
        tracing::warn!("Środowisko nie-UNIX - vHSM działa w trybie mock.");
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(unix)]
async fn run_unix_listener(state: Arc<RwLock<VhsmState>>) -> Result<(), Box<dyn std::error::Error>> {
    use aes_gcm::{aead::Aead, Nonce};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    const SOCKET_PATH: &str = "/run/vhsm/vhsm.sock";

    if let Some(parent) = Path::new(SOCKET_PATH).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if Path::new(SOCKET_PATH).exists() {
        tokio::fs::remove_file(SOCKET_PATH).await?;
    }

    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))?;

    tracing::info!("vHSM Daemon oczekuje na inicjalizację kluczem na: {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65536];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 { return; }

                        let response = match serde_json::from_slice::<VhsmRequest>(&buffer[..n]) {
                            Ok(VhsmRequest::InitMasterKey { master_key_hex }) => {
                                match hex::decode(&master_key_hex) {
                                    Ok(key_bytes) => match Aes256Gcm::new_from_slice(&key_bytes) {
                                        Ok(cipher) => {
                                            let mut w = state_clone.write().await;
                                            w.cipher = Some(cipher);
                                            tracing::info!("vHSM został pomyślnie ODBLOKOWANY kluczem głównym.");
                                            VhsmResponse::InitSuccess
                                        }
                                        Err(e) => VhsmResponse::Error { error: e.to_string() },
                                    },
                                    Err(e) => VhsmResponse::Error { error: format!("Błąd klucza hex: {}", e) },
                                }
                            }
                            Ok(VhsmRequest::Status) => {
                                let r = state_clone.read().await;
                                VhsmResponse::StatusResponse { is_unlocked: r.cipher.is_some() }
                            }
                            Ok(VhsmRequest::Encrypt { plaintext }) => {
                                let r = state_clone.read().await;
                                if let Some(ref cipher) = r.cipher {
                                    let nonce_bytes: [u8; 12] = rand::random();
                                    let nonce = Nonce::from_slice(&nonce_bytes);
                                    match cipher.encrypt(nonce, plaintext.as_ref()) {
                                        Ok(ciphertext) => VhsmResponse::EncryptSuccess {
                                            nonce: nonce_bytes.to_vec(),
                                            ciphertext,
                                        },
                                        Err(e) => VhsmResponse::Error { error: e.to_string() },
                                    }
                                } else {
                                    VhsmResponse::Error { error: "vHSM jest ZABLOKOWANY. Wymagana ceremonia inicjalizacji.".into() }
                                }
                            }
                            Ok(VhsmRequest::Decrypt { nonce, ciphertext }) => {
                                let r = state_clone.read().await;
                                if let Some(ref cipher) = r.cipher {
                                    if nonce.len() != 12 {
                                        VhsmResponse::Error { error: "Nieprawidłowy rozmiar Nonce".into() }
                                    } else {
                                        let nonce_slice = Nonce::from_slice(&nonce);
                                        match cipher.decrypt(nonce_slice, ciphertext.as_ref()) {
                                            Ok(plaintext) => VhsmResponse::DecryptSuccess { plaintext },
                                            Err(e) => VhsmResponse::Error { error: e.to_string() },
                                        }
                                    }
                                } else {
                                    VhsmResponse::Error { error: "vHSM jest ZABLOKOWANY. Wymagana ceremonia inicjalizacji.".into() }
                                }
                            }
                            Err(e) => VhsmResponse::Error { error: format!("Błąd deserializacji: {}", e) },
                        };

                        if let Ok(resp_bytes) = serde_json::to_vec(&response) {
                            let _ = stream.write_all(&resp_bytes).await;
                        }
                    }
                });
            }
            Err(e) => tracing::error!("Błąd gniazda UNIX: {}", e),
        }
    }
}