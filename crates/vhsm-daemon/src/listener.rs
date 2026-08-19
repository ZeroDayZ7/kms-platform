#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use kms_core::hsm::protocol::HsmRequest;
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::RwLock,
};

#[cfg(unix)]
use crate::handler;
#[cfg(unix)]
use crate::state::VhsmState;

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
                        Ok(req) => handler::handle_request(req, state_clone).await,
                        Err(err) => kms_core::hsm::protocol::HsmResponse::Error {
                            code: 400,
                            message: format!("Failed to deserialize HSM request: {err}"),
                        },
                    };

                    let res_payload = serde_json::to_vec(&response).unwrap_or_default();
                    let frame_len = res_payload.len() as u32;

                    let mut frame = Vec::with_capacity(4 + res_payload.len());
                    frame.extend_from_slice(&frame_len.to_be_bytes());
                    frame.extend_from_slice(&res_payload);

                    let _ = stream.write_all(&frame).await;
                });
            }
            Err(err) => tracing::error!("Błąd gniazda UNIX: {}", err),
        }
    }
}
