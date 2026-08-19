use aes_gcm::{aead::KeyInit, Aes256Gcm};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum VhsmRequest {
    Encrypt { plaintext: Vec<u8> },
    Decrypt { nonce: Vec<u8>, ciphertext: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum VhsmResponse {
    EncryptSuccess { nonce: Vec<u8>, ciphertext: Vec<u8> },
    DecryptSuccess { plaintext: Vec<u8> },
    Error { error: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Uruchamianie vHSM Daemon...");

    let master_key_bytes = std::env::var("VHSM_MASTER_KEY").unwrap_or_else(|_| {
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()
    });
    let key_bytes = hex::decode(master_key_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

    #[cfg(unix)]
    {
        run_unix_listener(cipher).await?;
    }

    #[cfg(not(unix))]
    {
        let _ = cipher;
        tracing::warn!(
            "Środowisko nie-UNIX (host Windows) – vHSM Daemon działa w trybie mock/stub."
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(unix)]
async fn run_unix_listener(cipher: Aes256Gcm) -> Result<(), Box<dyn std::error::Error>> {
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

    tracing::info!("vHSM Daemon gotowy do pracy na gnieździe: {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let cipher_clone = cipher.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65536];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 {
                            return;
                        }

                        let response = match serde_json::from_slice::<VhsmRequest>(&buffer[..n]) {
                            Ok(VhsmRequest::Encrypt { plaintext }) => {
                                let nonce_bytes: [u8; 12] = rand::random();
                                let nonce = Nonce::from_slice(&nonce_bytes);

                                match cipher_clone.encrypt(nonce, plaintext.as_ref()) {
                                    Ok(ciphertext) => VhsmResponse::EncryptSuccess {
                                        nonce: nonce_bytes.to_vec(),
                                        ciphertext,
                                    },
                                    Err(e) => VhsmResponse::Error {
                                        error: e.to_string(),
                                    },
                                }
                            }
                            Ok(VhsmRequest::Decrypt { nonce, ciphertext }) => {
                                if nonce.len() != 12 {
                                    VhsmResponse::Error {
                                        error: "Nieprawidłowy rozmiar Nonce".into(),
                                    }
                                } else {
                                    let nonce_slice = Nonce::from_slice(&nonce);
                                    match cipher_clone.decrypt(nonce_slice, ciphertext.as_ref()) {
                                        Ok(plaintext) => VhsmResponse::DecryptSuccess { plaintext },
                                        Err(e) => VhsmResponse::Error {
                                            error: e.to_string(),
                                        },
                                    }
                                }
                            }
                            Err(e) => VhsmResponse::Error {
                                error: format!("Błąd deserializacji: {}", e),
                            },
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
