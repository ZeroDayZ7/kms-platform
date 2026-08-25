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

        // src/handler.rs
        HsmRequest::GenerateCeremony {
            threshold,
            total_shares,
        } => {
            let guard = state.read().await;

            if guard.initialized {
                return HsmResponse::Error {
                    code: 400,
                    message: "vHSM is already initialized. Reset required to re-run ceremony."
                        .to_string(),
                };
            }

            drop(guard);

            match crypto::generate_and_split_master_key(total_shares, threshold) {
                Ok((raw_master_key, shares)) => {
                    let mut guard = state.write().await;

                    guard.master_key = Some(raw_master_key);
                    guard.initialized = true;
                    guard.active_key_version = 1;
                    guard.cancel_unseal_timer();

                    // LOGI DIAGNOSTYCZNE
                    tracing::info!("vHSM wygenerował wewnątrz nowy Master Key i podzielił go SSS.");

                    HsmResponse::CeremonyGenerated { shares }
                }

                Err(msg) => HsmResponse::Error {
                    code: 500,
                    message: msg,
                },
            }
        }

        HsmRequest::InitMasterKey { threshold, shares } => {
            if threshold == 0 {
                return HsmResponse::Error {
                    code: 400,
                    message: "Threshold must be greater than zero.".to_string(),
                };
            }

            if shares.len() < threshold as usize {
                return HsmResponse::Error {
                    code: 422,
                    message: format!(
                        "Insufficient shares: {} provided, {} required.",
                        shares.len(),
                        threshold
                    ),
                };
            }

            match crypto::reconstruct_master_key(&shares) {
                Ok(recovered) => {
                    let mut guard = state.write().await;

                    guard.master_key = Some(recovered);
                    guard.initialized = true;
                    guard.active_key_version = 1;
                    guard.cancel_unseal_timer();
                    guard.cancel_unseal_timer();

                    tracing::info!("vHSM został pomyślnie odblokowany kluczem głównym.");

                    HsmResponse::MasterKeyInitialized
                }

                Err(msg) => HsmResponse::Error {
                    code: 422,
                    message: msg,
                },
            }
        }

        HsmRequest::Encrypt {
            key_id,
            key_version,
            plaintext,
        } => {
            if key_id != "master_key" {
                return HsmResponse::Error {
                    code: 404,
                    message: format!("Unknown key id: {key_id}"),
                };
            }

            let version = {
                let guard = state.read().await;
                if guard.master_key.is_none() {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }

                if let Some(requested_version) = key_version {
                    if requested_version != guard.active_key_version {
                        return HsmResponse::Error {
                            code: 409,
                            message: format!(
                                "Requested key version {requested_version} does not match active key version {}",
                                guard.active_key_version
                            ),
                        };
                    }
                }

                guard.active_key_version
            };

            let should_cancel_unseal = {
                let guard = state.read().await;
                guard.master_key.is_some()
            };
            if should_cancel_unseal {
                let mut guard = state.write().await;
                guard.cancel_unseal_timer();
            }

            let result = {
                let guard = state.read().await;
                match guard.master_key.as_ref() {
                    Some(key) => crypto::encrypt_bytes(key, plaintext.as_ref()),
                    None => return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first.".to_string(),
                    },
                }
            };

            match result {
                Ok(ciphertext) => HsmResponse::Encrypted {
                    ciphertext,
                    key_version: version,
                },
                Err(msg) => HsmResponse::Error {
                    code: 500,
                    message: msg,
                },
            }
        }

        HsmRequest::Decrypt {
            key_id,
            key_version,
            ciphertext,
        } => {
            if key_id != "master_key" {
                return HsmResponse::Error {
                    code: 404,
                    message: format!("Unknown key id: {key_id}"),
                };
            }

            let version = {
                let guard = state.read().await;
                if guard.master_key.is_none() {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }

                if let Some(requested_version) = key_version {
                    if requested_version != guard.active_key_version {
                        return HsmResponse::Error {
                            code: 409,
                            message: format!(
                                "Requested key version {requested_version} does not match active key version {}",
                                guard.active_key_version
                            ),
                        };
                    }
                }

                guard.active_key_version
            };

            let should_cancel_unseal = {
                let guard = state.read().await;
                guard.master_key.is_some()
            };
            if should_cancel_unseal {
                let mut guard = state.write().await;
                guard.cancel_unseal_timer();
            }

            let result = {
                let guard = state.read().await;
                match guard.master_key.as_ref() {
                    Some(key) => crypto::decrypt_bytes(key, ciphertext.as_ref()),
                    None => return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first.".to_string(),
                    },
                }
            };

            match result {
                Ok(plaintext) => HsmResponse::Decrypted {
                    plaintext,
                    key_version: version,
                },
                Err(msg) => HsmResponse::Error {
                    code: 500,
                    message: msg,
                },
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::handle_request;
    use crate::state::VhsmState;
    use kms_core::hsm::protocol::{HsmRequest, HsmResponse};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn encrypt_returns_active_key_version() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 7;
            guard.master_key = Some(vec![0u8; 32]);
        }

        let result = handle_request(
            HsmRequest::Encrypt {
                key_id: "master_key".to_string(),
                key_version: None,
                plaintext: b"hello".to_vec(),
            },
            state,
        )
        .await;

        match result {
            HsmResponse::Encrypted { key_version, .. } => assert_eq!(key_version, 7),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_rejects_mismatched_key_version() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 9;
            guard.master_key = Some(vec![0u8; 32]);
        }

        let result = handle_request(
            HsmRequest::Encrypt {
                key_id: "master_key".to_string(),
                key_version: Some(2),
                plaintext: b"hello".to_vec(),
            },
            state,
        )
        .await;

        match result {
            HsmResponse::Error { code, .. } => assert_eq!(code, 409),
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
