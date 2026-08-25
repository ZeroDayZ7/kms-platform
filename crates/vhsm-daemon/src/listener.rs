#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use kms_core::hsm::protocol::HsmRequest;
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::{RwLock, Semaphore},
};

#[cfg(unix)]
use crate::handler;
#[cfg(unix)]
use crate::state::VhsmState;

// Stałe konfiguracyjne bezpieczeństwa vHSM (zabezpieczone dla platformy Unix)
#[cfg(unix)]
const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64 KB limit dla żądania i odpowiedzi
#[cfg(unix)]
const IO_TIMEOUT: Duration = Duration::from_secs(5); // 5s na operacje I/O
#[cfg(unix)]
const MAX_CONCURRENT_REQUESTS: usize = 100; // Limit równoległych operacji kryptograficznych

#[cfg(unix)]
pub async fn run_unix_listener(
    state: Arc<RwLock<VhsmState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    const SOCKET_PATH: &str = "/run/vhsm/vhsm.sock";

    if let Some(parent) = Path::new(SOCKET_PATH).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if Path::new(SOCKET_PATH).exists() {
        tokio::fs::remove_file(SOCKET_PATH).await?;
    }

    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))?;

    // Semafor do kontrolowania maksymalnej liczby współbieżnych żądań HSM
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));

    tracing::info!(
        "vHSM Daemon oczekuje na inicjalizację kluczem na: {}",
        SOCKET_PATH
    );

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let state_clone = Arc::clone(&state);
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(
                            "Odrzucono połączenie: osiągnięto limit współbieżnych zadań HSM"
                        );
                        continue;
                    }
                };

                tokio::spawn(async move {
                    // Pozwala na zwolnienie semafora po zakończeniu taska
                    let _permit = permit;

                    // 1. Odczyt długości ramki (4 bajty) z timeoutem
                    let mut len_buf = [0u8; 4];
                    if tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut len_buf))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Timeout lub błąd odczytu nagłówka ramki vHSM");
                        return;
                    }

                    let len = u32::from_be_bytes(len_buf) as usize;

                    // 2. Weryfikacja limitu payloadu PRZED alokacją pamięci
                    if len > MAX_PAYLOAD_SIZE {
                        tracing::warn!(
                            "Odrzucono zbyt dużą ramkę requestu: {} bajtów (max: {})",
                            len,
                            MAX_PAYLOAD_SIZE
                        );
                        return;
                    }

                    // 3. Odczyt treści żądania z timeoutem
                    let mut payload = vec![0u8; len];
                    if tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut payload))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Timeout lub błąd odczytu payloadu vHSM");
                        return;
                    }

                    // 4. Deserializacja i obsługa żądania
                    let response = match serde_json::from_slice::<HsmRequest>(&payload) {
                        Ok(req) => handler::handle_request(req, state_clone).await,
                        Err(err) => kms_core::hsm::protocol::HsmResponse::Error {
                            code: 400,
                            message: format!("Failed to deserialize HSM request: {err}"),
                        },
                    };

                    // 5. Bezpieczna serializacja odpowiedzi
                    let res_payload = match serde_json::to_vec(&response) {
                        Ok(payload) => payload,
                        Err(err) => {
                            tracing::error!("Nie udało się serializować odpowiedzi HSM: {}", err);
                            return;
                        }
                    };

                    // 6. Weryfikacja limitu rozmiaru odpowiedzi
                    if res_payload.len() > MAX_PAYLOAD_SIZE {
                        tracing::error!(
                            "Odpowiedź HSM przekracza dopuszczalny limit: {} bajtów",
                            res_payload.len()
                        );
                        return;
                    }

                    // 7. Przygotowanie i wysłanie ramki odpowiedzi
                    let frame_len = res_payload.len() as u32;
                    let mut frame = Vec::with_capacity(4 + res_payload.len());
                    frame.extend_from_slice(&frame_len.to_be_bytes());
                    frame.extend_from_slice(&res_payload);

                    if let Err(err) =
                        tokio::time::timeout(IO_TIMEOUT, stream.write_all(&frame)).await
                    {
                        tracing::warn!("Nie udało się wysłać odpowiedzi do klienta: {:?}", err);
                    }
                });
            }
            Err(err) => tracing::error!("Błąd gniazda UNIX: {}", err),
        }
    }
}
