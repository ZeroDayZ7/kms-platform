#[cfg(unix)]
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};
#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let socket = env::var("CRYPTO__HSM_SOCKET_PATH").unwrap_or_else(|_| "/run/vhsm/vhsm.sock".to_string());

    // Connect to Unix socket and send framed Ping
    use tokio::net::UnixStream;
    use kms_core::hsm::client::framed_message;

    match UnixStream::connect(&socket).await {
        Ok(mut stream) => {
            let req = HsmRequest::Ping;
            let payload = match serde_json::to_vec(&req) {
                Ok(p) => p,
                Err(_) => return std::process::ExitCode::from(2),
            };
            let frame = match framed_message(&payload) {
                Ok(f) => f,
                Err(_) => return std::process::ExitCode::from(2),
            };

            if tokio::time::timeout(Duration::from_secs(2), stream.write_all(&frame)).await.is_err() {
                return std::process::ExitCode::from(3);
            }

            // read response len
            use tokio::io::AsyncReadExt;
            let mut len_buf = [0u8; 4];
            if tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf)).await.is_err() {
                return std::process::ExitCode::from(4);
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 || len > 1024 * 1024 {
                return std::process::ExitCode::from(5);
            }
            let mut payload = vec![0u8; len];
            if tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut payload)).await.is_err() {
                return std::process::ExitCode::from(6);
            }

            match serde_json::from_slice::<HsmResponse>(&payload) {
                Ok(HsmResponse::Pong) => std::process::ExitCode::from(0),
                _ => std::process::ExitCode::from(7),
            }
        }
        Err(_) => std::process::ExitCode::from(1),
    }
}

#[cfg(not(unix))]
fn main() {}
