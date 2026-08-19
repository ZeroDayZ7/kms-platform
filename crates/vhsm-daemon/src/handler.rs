#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::sync::RwLock;

#[cfg(unix)]
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

#[cfg(unix)]
use crate::crypto;
#[cfg(unix)]
use crate::state::VhsmState;

#[cfg(unix)]
pub async fn handle_request(request: HsmRequest, state: Arc<RwLock<VhsmState>>) -> HsmResponse {
    match request {
        HsmRequest::Ping => HsmResponse::Pong,
        HsmRequest::Status => {
            let guard = state.read().await;
            HsmResponse::StatusInfo {
                initialized: guard.initialized,
                active_key_version: guard.active_key_version,
            }
        }
        HsmRequest::InitMasterKey { shares } => match crypto::reconstruct_master_key(&shares) {
            Ok(recovered) => {
                let mut guard = state.write().await;
                guard.master_key = Some(recovered);
                guard.initialized = true;
                guard.active_key_version = 1;
                tracing::info!("vHSM został pomyślnie odblokowany kluczem głównym.");
                HsmResponse::MasterKeyInitialized
            }
            Err(msg) => HsmResponse::Error {
                code: 422,
                message: msg,
            },
        },
        HsmRequest::Encrypt {
            key_id,
            key_version: _,
            plaintext,
        } => {
            if key_id != "master_key" {
                return HsmResponse::Error {
                    code: 404,
                    message: format!("Unknown key id: {key_id}"),
                };
            }

            let master_key = state.read().await.master_key.clone();
            match master_key {
                Some(key) => match crypto::encrypt_bytes(&key, plaintext.as_ref()) {
                    Ok(ciphertext) => HsmResponse::Encrypted { ciphertext },
                    Err(msg) => HsmResponse::Error {
                        code: 500,
                        message: msg,
                    },
                },
                None => HsmResponse::Error {
                    code: 403,
                    message: "vHSM is locked. Master key must be initialized first.".to_string(),
                },
            }
        }
        HsmRequest::Decrypt {
            key_id,
            key_version: _,
            ciphertext,
        } => {
            if key_id != "master_key" {
                return HsmResponse::Error {
                    code: 404,
                    message: format!("Unknown key id: {key_id}"),
                };
            }

            let master_key = state.read().await.master_key.clone();
            match master_key {
                Some(key) => match crypto::decrypt_bytes(&key, ciphertext.as_ref()) {
                    Ok(plaintext) => HsmResponse::Decrypted { plaintext },
                    Err(msg) => HsmResponse::Error {
                        code: 500,
                        message: msg,
                    },
                },
                None => HsmResponse::Error {
                    code: 403,
                    message: "vHSM is locked. Master key must be initialized first.".to_string(),
                },
            }
        }
    }
}
