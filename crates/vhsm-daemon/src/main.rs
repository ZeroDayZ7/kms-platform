use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

#[cfg(unix)]
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, Nonce,
};
#[cfg(unix)]
use kms_core::{
    crypto::sss::{combine_shares, SecretShare},
    hsm::protocol::{HsmRequest, HsmResponse},
};
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

#[allow(dead_code)]
pub struct VhsmState {
    pub initialized: bool,
    pub active_key_version: u32,
    pub master_key: Option<Vec<u8>>,
}

impl VhsmState {
    pub fn zeroize_key(&mut self) {
        if let Some(ref mut key) = self.master_key {
            key.zeroize();
        }
        self.master_key = None;
        self.initialized = false;
        self.active_key_version = 0;
    }
}

impl Drop for VhsmState {
    fn drop(&mut self) {
        self.zeroize_key();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon w trybie zero-trust...");

    let state = Arc::new(RwLock::new(VhsmState {
        initialized: false,
        active_key_version: 0,
        master_key: None,
    }));

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
async fn run_unix_listener(
    state: Arc<RwLock<VhsmState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const SOCKET_PATH: &str = "/run/vhsm/vhsm.sock";

    if let Some(parent) = Path::new(SOCKET_PATH).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if Path::new(SOCKET_PATH).exists() {
        tokio::fs::remove_file(SOCKET_PATH).await?;
    }

    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))?;

    tracing::info!(
        "vHSM Daemon oczekuje na inicjalizację kluczem na: {}",
        SOCKET_PATH
    );

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }

                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; len];
                    if stream.read_exact(&mut payload).await.is_err() {
                        return;
                    }

                    let response = match serde_json::from_slice::<HsmRequest>(&payload) {
                        Ok(HsmRequest::Ping) => HsmResponse::Pong,
                        Ok(HsmRequest::Status) => {
                            let guard = state_clone.read().await;
                            HsmResponse::StatusInfo {
                                initialized: guard.initialized,
                                active_key_version: guard.active_key_version,
                            }
                        }
                        Ok(HsmRequest::InitMasterKey { shares }) => {
                            if shares.is_empty() {
                                HsmResponse::Error {
                                    code: 400,
                                    message: "At least one share is required".to_string(),
                                }
                            } else {
                                let share_items: Vec<SecretShare> = shares
                                    .iter()
                                    .enumerate()
                                    .map(|(index, value)| SecretShare {
                                        index: (index as u8) + 1,
                                        value: value.clone(),
                                    })
                                    .collect();

                                match combine_shares(&share_items) {
                                    Ok(recovered) => {
                                        if recovered.len() != 32 {
                                            HsmResponse::Error {
                                                code: 422,
                                                message: "Recovered master key must be 32 bytes"
                                                    .to_string(),
                                            }
                                        } else {
                                            let mut guard = state_clone.write().await;
                                            guard.master_key = Some(recovered.clone());
                                            guard.initialized = true;
                                            guard.active_key_version = 1;
                                            tracing::info!("vHSM został pomyślnie odblokowany kluczem głównym.");
                                            let _ = recovered;
                                            HsmResponse::MasterKeyInitialized
                                        }
                                    }
                                    Err(err) => HsmResponse::Error {
                                        code: 500,
                                        message: format!(
                                            "Failed to reconstruct master key from shares: {err}"
                                        ),
                                    },
                                }
                            }
                        }
                        Ok(HsmRequest::Encrypt {
                            key_id,
                            key_version,
                            plaintext,
                        }) => {
                            if key_id != "master_key" {
                                HsmResponse::Error {
                                    code: 404,
                                    message: format!("Unknown key id: {key_id}"),
                                }
                            } else {
                                let master_key = {
                                    let guard = state_clone.read().await;
                                    guard.master_key.clone()
                                };

                                match master_key {
                                    Some(key) => {
                                        let cipher = match Aes256Gcm::new_from_slice(&key) {
                                            Ok(cipher) => cipher,
                                            Err(err) => {
                                                return HsmResponse::Error {
                                                    code: 500,
                                                    message: format!(
                                                        "Failed to initialize AES-GCM: {err}"
                                                    ),
                                                };
                                            }
                                        };
                                        let mut nonce_bytes = [0u8; 12];
                                        OsRng.fill_bytes(&mut nonce_bytes);
                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                        match cipher.encrypt(nonce, plaintext.as_ref()) {
                                            Ok(ciphertext) => HsmResponse::Encrypted { ciphertext },
                                            Err(err) => HsmResponse::Error {
                                                code: 500,
                                                message: format!("Encryption failed: {err}"),
                                            },
                                        }
                                    }
                                    None => HsmResponse::Error {
                                        code: 403,
                                        message:
                                            "vHSM is locked. Master key must be initialized first."
                                                .to_string(),
                                    },
                                }
                            }
                        }
                        Ok(HsmRequest::Decrypt {
                            key_id,
                            key_version,
                            ciphertext,
                        }) => {
                            if key_id != "master_key" {
                                HsmResponse::Error {
                                    code: 404,
                                    message: format!("Unknown key id: {key_id}"),
                                }
                            } else {
                                let master_key = {
                                    let guard = state_clone.read().await;
                                    guard.master_key.clone()
                                };

                                match master_key {
                                    Some(key) => {
                                        let cipher = match Aes256Gcm::new_from_slice(&key) {
                                            Ok(cipher) => cipher,
                                            Err(err) => {
                                                return HsmResponse::Error {
                                                    code: 500,
                                                    message: format!(
                                                        "Failed to initialize AES-GCM: {err}"
                                                    ),
                                                };
                                            }
                                        };
                                        let mut nonce_bytes = [0u8; 12];
                                        OsRng.fill_bytes(&mut nonce_bytes);
                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                        let _ = key_version;
                                        match cipher.decrypt(nonce, ciphertext.as_ref()) {
                                            Ok(plaintext) => HsmResponse::Decrypted { plaintext },
                                            Err(err) => HsmResponse::Error {
                                                code: 500,
                                                message: format!("Decryption failed: {err}"),
                                            },
                                        }
                                    }
                                    None => HsmResponse::Error {
                                        code: 403,
                                        message:
                                            "vHSM is locked. Master key must be initialized first."
                                                .to_string(),
                                    },
                                }
                            }
                        }
                        Err(err) => HsmResponse::Error {
                            code: 400,
                            message: format!("Failed to deserialize HSM request: {err}"),
                        },
                    };

                    let payload = serde_json::to_vec(&response).unwrap_or_default();
                    let frame = {
                        let len = payload.len() as u32;
                        let mut bytes = Vec::with_capacity(4 + payload.len());
                        bytes.extend_from_slice(&len.to_be_bytes());
                        bytes.extend_from_slice(&payload);
                        bytes
                    };
                    let _ = stream.write_all(&frame).await;
                });
            }
            Err(err) => tracing::error!("Błąd gniazda UNIX: {}", err),
        }
    }
}
