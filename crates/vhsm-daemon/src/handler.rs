#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use tokio::sync::RwLock;

#[cfg(unix)]
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};
#[cfg(unix)]
use zeroize::Zeroizing;

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

                    tracing::info!("vHSM został pomyślnie odblokowany kluczem głównym.");

                    HsmResponse::MasterKeyInitialized
                }

                Err(msg) => HsmResponse::Error {
                    code: 422,
                    message: msg,
                },
            }
        }

        HsmRequest::GenerateKek { algorithm } => {
            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(key) => key,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }
            };

            let root_key_version = guard.active_key_version;
            let algorithm_name = algorithm.trim();
            if !matches!(algorithm_name, "AES256GCM") {
                return HsmResponse::Error {
                    code: 400,
                    message: "Unsupported KEK algorithm. Only AES256GCM is supported.".to_string(),
                };
            }

            let mut kek = Zeroizing::new([0u8; 32]);
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(kek.as_mut());

            let wrapped_kek = match crypto::encrypt_bytes(root_key.as_ref(), kek.as_ref()) {
                Ok(value) => value,
                Err(msg) => {
                    return HsmResponse::Error {
                        code: 500,
                        message: msg,
                    };
                }
            };

            let kek_version = 1u32;
            HsmResponse::KekGenerated {
                wrapped_kek,
                kek_version,
                root_key_version,
                algorithm: algorithm_name.to_string(),
            }
        }

        HsmRequest::GenerateDataKey {
            wrapped_kek,
            kek_version,
            algorithm,
        } => {
            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(key) => key,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }
            };

            let root_key_version = guard.active_key_version;
            let expected_kek_version = 1u32;
            if let Some(requested_version) = kek_version {
                if requested_version != expected_kek_version {
                    return HsmResponse::Error {
                        code: 409,
                        message: format!(
                            "Requested KEK version {requested_version} does not match active KEK version {expected_kek_version}"
                        ),
                    };
                }
            }

            if !matches!(algorithm.trim(), "AES256GCM") {
                return HsmResponse::Error {
                    code: 400,
                    message: "Unsupported DEK algorithm. Only AES256GCM is supported.".to_string(),
                };
            }

            let kek = match crypto::decrypt_bytes(root_key.as_ref(), &wrapped_kek) {
                Ok(value) => value,
                Err(msg) => {
                    return HsmResponse::Error {
                        code: 500,
                        message: format!("Failed to unwrap KEK: {msg}"),
                    };
                }
            };

            let mut dek = Zeroizing::new([0u8; 32]);
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(dek.as_mut());

            let wrapped_dek = match crypto::encrypt_bytes(kek.as_ref(), dek.as_ref()) {
                Ok(value) => value,
                Err(msg) => {
                    return HsmResponse::Error {
                        code: 500,
                        message: msg,
                    };
                }
            };

            // Boundary conversion: the serialized HSM protocol returns Vec<u8> for response payloads;
            // the secret material itself remains protected by Zeroizing until this point.
            HsmResponse::DataKeyGenerated {
                plaintext_dek: dek.as_ref().to_vec(),
                wrapped_dek,
                kek_version: expected_kek_version,
                root_key_version,
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

            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(k) => k,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }
            };

            if let Some(req_ver) = key_version {
                if req_ver != guard.active_key_version {
                    return HsmResponse::Error {
                        code: 409,
                        message: format!(
                            "Requested key version {req_ver} does not match active key version {}",
                            guard.active_key_version
                        ),
                    };
                }
            }

            let version = guard.active_key_version;
            let res = crypto::encrypt_bytes(root_key.as_ref(), plaintext.as_ref());

            match res {
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

            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(k) => k,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first."
                            .to_string(),
                    };
                }
            };

            if let Some(req_ver) = key_version {
                if req_ver != guard.active_key_version {
                    return HsmResponse::Error {
                        code: 409,
                        message: format!(
                            "Requested key version {req_ver} does not match active key version {}",
                            guard.active_key_version
                        ),
                    };
                }
            }

            let version = guard.active_key_version;
            let res = crypto::decrypt_bytes(root_key.as_ref(), ciphertext.as_ref());

            match res {
                Ok(plaintext) => {
                    // Boundary conversion: protocol response needs Vec<u8> for JSON serialization,
                    // while secret material remains protected by Zeroizing inside vHSM until here.
                    HsmResponse::Decrypted {
                        plaintext: plaintext.to_vec(),
                        key_version: version,
                    }
                }
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
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn encrypt_returns_active_key_version() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 7;
            guard.master_key = Some(Zeroizing::new(vec![0u8; 32]));
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
            guard.master_key = Some(Zeroizing::new(vec![0u8; 32]));
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

    #[tokio::test]
    async fn generate_kek_returns_wrapped_material_only() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 3;
            guard.master_key = Some(Zeroizing::new(vec![0u8; 32]));
        }

        let response = handle_request(
            HsmRequest::GenerateKek {
                algorithm: "AES256GCM".to_string(),
            },
            state,
        )
        .await;

        match response {
            HsmResponse::KekGenerated {
                wrapped_kek,
                kek_version,
                root_key_version,
                algorithm,
            } => {
                assert!(!wrapped_kek.is_empty());
                assert_eq!(kek_version, 1);
                assert_eq!(root_key_version, 3);
                assert_eq!(algorithm, "AES256GCM");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn generate_data_key_returns_dek_without_exposing_kek() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 5;
            guard.master_key = Some(Zeroizing::new(vec![42u8; 32]));
        }

        let kek_response = handle_request(
            HsmRequest::GenerateKek {
                algorithm: "AES256GCM".to_string(),
            },
            state.clone(),
        )
        .await;
        let kek_wrap = match kek_response {
            HsmResponse::KekGenerated { wrapped_kek, .. } => wrapped_kek,
            other => panic!("unexpected KEK response: {other:?}"),
        };

        let result = handle_request(
            HsmRequest::GenerateDataKey {
                wrapped_kek: kek_wrap,
                kek_version: Some(1),
                algorithm: "AES256GCM".to_string(),
            },
            state,
        )
        .await;

        match result {
            HsmResponse::DataKeyGenerated {
                plaintext_dek,
                wrapped_dek,
                kek_version,
                root_key_version,
            } => {
                assert_eq!(plaintext_dek.len(), 32);
                assert!(!wrapped_dek.is_empty());
                assert_eq!(kek_version, 1);
                assert_eq!(root_key_version, 5);
            }
            other => panic!("unexpected data key response: {other:?}"),
        }
    }
}
