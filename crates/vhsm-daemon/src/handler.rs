#[cfg(any(unix, test))]
use base64::Engine;
#[cfg(any(unix, test))]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(any(unix, test))]
use std::sync::Arc;

#[cfg(any(unix, test))]
use tokio::sync::RwLock;

#[cfg(any(unix, test))]
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};
#[cfg(any(unix, test))]
use zeroize::Zeroizing;

#[cfg(any(unix, test))]
mod local_crypto {
    #[cfg(not(test))]
    pub use crate::crypto::*;

    #[cfg(test)]
    pub mod test_impl {
        use aes_gcm::{
            Aes256Gcm, KeyInit, Nonce,
            aead::{Aead, OsRng, rand_core::RngCore},
        };
        use kms_core::crypto::sss::{SecretShare, combine_shares, split_shares};
        use std::collections::HashSet;
        use zeroize::{Zeroize, Zeroizing};

        pub fn generate_and_split_master_key(
            total: u8,
            threshold: u8,
        ) -> Result<(Zeroizing<Vec<u8>>, Vec<(u8, String)>), String> {
            let master_key = kms_core::crypto::keys::generate_master_key();
            let raw_bytes = Zeroizing::new(master_key.as_bytes().to_vec());

            let shares = split_shares(&master_key, total, threshold)
                .map_err(|e| format!("Failed to split master key: {e}"))?;

            Ok((raw_bytes, shares))
        }

        pub fn reconstruct_master_key(
            shares: &[(u8, String)],
        ) -> Result<Zeroizing<Vec<u8>>, String> {
            if shares.is_empty() {
                return Err("At least one share is required".to_string());
            }

            let mut seen_indices = HashSet::with_capacity(shares.len());
            for (index, _) in shares {
                if !seen_indices.insert(index) {
                    return Err(format!("Duplicate share index detected: {index}"));
                }
            }

            let mut secret_shares = shares
                .iter()
                .map(|(index, value)| SecretShare {
                    index: *index,
                    value: Zeroizing::new(value.clone()),
                })
                .collect::<Vec<_>>();

            let recovered_raw = combine_shares(&secret_shares)
                .map_err(|err| format!("Failed to reconstruct master key from shares: {err}"));

            secret_shares.iter_mut().for_each(|s| s.value.zeroize());

            let recovered = Zeroizing::new(recovered_raw?);

            if recovered.len() != 32 {
                return Err("Recovered master key must be 32 bytes".to_string());
            }

            Ok(recovered)
        }

        pub fn encrypt_bytes(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|err| format!("Failed to initialize AES-GCM: {err}"))?;

            let mut nonce_bytes = Zeroizing::new([0u8; 12]);
            OsRng.fill_bytes(nonce_bytes.as_mut());

            let nonce = Nonce::from_slice(nonce_bytes.as_ref());

            let mut ciphertext = cipher
                .encrypt(nonce, plaintext)
                .map_err(|err| format!("Encryption failed: {err}"))?;

            let mut payload = nonce_bytes.to_vec();
            payload.append(&mut ciphertext);

            Ok(payload)
        }

        pub fn decrypt_bytes(key: &[u8], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
            if payload.len() < 12 {
                return Err("Ciphertext payload too short".to_string());
            }

            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|err| format!("Failed to initialize AES-GCM: {err}"))?;

            let (nonce_bytes, raw_ciphertext) = payload.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            let plaintext = cipher
                .decrypt(nonce, raw_ciphertext)
                .map_err(|err| format!("Decryption failed: {err}"))?;

            Ok(Zeroizing::new(plaintext))
        }
    }

    #[cfg(test)]
    pub use test_impl::*;
}
#[cfg(any(unix, test))]
use local_crypto as crypto;

#[cfg(any(unix, test))]
use crate::state::VhsmState;

#[cfg(any(unix, test))]
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

        HsmRequest::GenerateRandomBytes { length } => {
            if length == 0 || length > 4096 {
                return HsmResponse::Error {
                    code: 400,
                    message: "Invalid random bytes length".to_string(),
                };
            }

            let mut random_bytes = vec![0u8; length];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut random_bytes);

            HsmResponse::RandomBytesGenerated { random_bytes }
        }

        HsmRequest::InitRootCa {
            ca_tag,
            common_name,
            validity_days,
            algorithm,
        } => {
            // Ensure vHSM is unsealed
            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(k) => k,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first.".to_string(),
                    };
                }
            };
            drop(guard);

            // Only support ECDSA P-256 for now
            if algorithm.trim() != "ECDSA_P256" {
                return HsmResponse::Error {
                    code: 400,
                    message: "Unsupported algorithm for InitRootCa".to_string(),
                };
            }

            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use rand::rngs::OsRng;

            // Generate signing key inside vHSM
            let signing_key = SigningKey::random(&mut OsRng);
            let private_bytes = signing_key.to_bytes();
            let private_vec = Zeroizing::new(private_bytes.to_vec());

            // Build public key and a simple self-signed cert using rcgen if available
            let verifying_key = signing_key.verifying_key();
            let public_key_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();

            // Create a minimal self-signed cert PEM using rcgen if possible
            let cert_pem = match (|| -> Result<String, String> {
                // attempt to create proper X.509 if rcgen is enabled
                #[cfg(feature = "use_rcgen")]
                {
                    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa, BasicConstraints};
                    let mut params = CertificateParams::new(vec![common_name.clone()]);
                    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                    params.public_key = Some(public_key_sec1.clone());
                    params.distinguished_name = DistinguishedName::new();
                    params
                        .distinguished_name
                        .push(DnType::CommonName, common_name.clone());
                    let cert = Certificate::from_params(params).map_err(|e| e.to_string())?;
                    let pem = cert.serialize_pem().map_err(|e| e.to_string())?;
                    Ok(pem)
                }
                #[cfg(not(feature = "use_rcgen"))]
                {
                    // Fallback minimal PEM placeholder
                    let b64 = BASE64_STANDARD.encode(&public_key_sec1);
                    let mut pem = String::new();
                    pem.push_str("-----BEGIN CERTIFICATE-----\n");
                    pem.push_str(&format!("# CN={}\n", common_name));
                    for chunk in b64.as_bytes().chunks(64) {
                        pem.push_str(&format!("{}\n", std::str::from_utf8(chunk).unwrap()));
                    }
                    pem.push_str("-----END CERTIFICATE-----\n");
                    Ok(pem)
                }
            })() {
                Ok(v) => v,
                Err(e) => {
                    return HsmResponse::Error { code: 500, message: e };
                }
            };

            // Encrypt private key bytes with master root key
            let guard2 = state.read().await;
            let root_key2 = guard2.master_key.as_ref().unwrap();
            let wrapped = match crypto::encrypt_bytes(root_key2.as_ref(), private_vec.as_ref()) {
                Ok(v) => v,
                Err(msg) => {
                    return HsmResponse::Error { code: 500, message: msg };
                }
            };

            // Keep encrypted blob only; do not store plaintext in KMS process
            let version = guard2.active_key_version;

            HsmResponse::RootCaKeyGenerated {
                encrypted_private_key: wrapped,
                public_key: public_key_sec1,
                master_key_version: version,
                algorithm: algorithm.clone(),
            }
        }

        HsmRequest::LoadRootCa { ca_tag, encrypted_private_key } => {
            // Ensure unsealed
            let guard = state.read().await;
            let root_key = match guard.master_key.as_ref() {
                Some(k) => k,
                None => {
                    return HsmResponse::Error {
                        code: 403,
                        message: "vHSM is locked. Master key must be initialized first.".to_string(),
                    };
                }
            };
            let version = guard.active_key_version;
            drop(guard);

            // Decrypt the encrypted_private_key into RAM (Zeroizing)
            let decrypted = match crypto::decrypt_bytes(root_key.as_ref(), &encrypted_private_key) {
                Ok(z) => z,
                Err(msg) => return HsmResponse::Error { code: 422, message: format!("Failed to decrypt provided CA blob: {}", msg) },
            };

            // Store loaded key in state.active_ca_keys
            let mut guard_w = state.write().await;
            guard_w
                .active_ca_keys
                .insert(ca_tag.clone(), Zeroizing::new(decrypted.to_vec()));

            HsmResponse::MasterKeyInitialized
        }

        HsmRequest::SignIntermediateCa { ca_tag, csr_pem, validity_days } => {
            // Ensure CA is loaded
            let guard = state.read().await;
            let key_opt = guard.active_ca_keys.get(&ca_tag).cloned();
            drop(guard);

            let sk_bytes = match key_opt {
                Some(z) => z,
                None => return HsmResponse::Error { code: 404, message: format!("CA with tag '{}' not loaded", ca_tag) },
            };

            // Parse CSR PEM to extract public key and subject (use x509-parser or rcgen if available)
            // We'll use rcgen if feature enabled for simplicity, else attempt minimal parsing.
            #[cfg(feature = "use_rcgen")]
            {
                use rcgen::CertificateParams;
                use x509_parser::pem::parse_x509_pem;
                use x509_parser::csr::parse_x509_p10;

                // parse PEM
                let (_rem, pem) = parse_x509_pem(csr_pem.as_bytes()).map_err(|_| HsmResponse::Error { code: 400, message: "Invalid CSR PEM".to_string() }).unwrap();
                let csr = parse_x509_p10(&pem.contents).map_err(|_| HsmResponse::Error { code: 400, message: "Invalid CSR ASN.1".to_string() }).unwrap();

                // Build certificate params and sign with private key bytes
                let mut params = CertificateParams::from_ca_cert_pem("", vec![]);
                // TODO: fill in params from CSR properly - this is non-trivial; fallback to not implemented
                return HsmResponse::Error { code: 501, message: "SignIntermediateCa CSR handling not fully implemented".to_string() };
            }

            // Without rcgen: return not implemented to avoid incorrect cert creation
            return HsmResponse::Error { code: 501, message: "SignIntermediateCa not implemented in this build".to_string() };
        }

        HsmRequest::GenerateCredential { password_length } => {
            let (root_key, key_version) = {
                let guard = state.read().await;
                let key = match guard.master_key.as_ref() {
                    Some(k) => k.clone(), // Klonujemy referencję/zawartość Zeroizing (lub trzymamy klucz)
                    None => {
                        return HsmResponse::Error {
                            code: 403,
                            message: "vHSM is locked. Master key must be initialized first."
                                .to_string(),
                        };
                    }
                };
                (key, guard.active_key_version)
            };

            if password_length == 0 || password_length > 1024 {
                return HsmResponse::Error {
                    code: 400,
                    message: "Invalid password length".to_string(),
                };
            }

            // Generate credential_id (non-secret, unpredictable)
            let mut id_bytes = [0u8; 16];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut id_bytes);
            let credential_id = hex::encode(id_bytes);

            // Generate password bytes securely and keep in Zeroizing
            let mut password_bytes = Zeroizing::new(vec![0u8; password_length]);
            rand::rngs::OsRng.fill_bytes(password_bytes.as_mut());

            // Encrypt (wrap) the raw password bytes with the root key
            let wrapped = match crypto::encrypt_bytes(root_key.as_ref(), password_bytes.as_ref()) {
                Ok(v) => v,
                Err(msg) => {
                    // ensure zeroize of password happens automatically
                    return HsmResponse::Error {
                        code: 500,
                        message: msg,
                    };
                }
            };

            // Convert password to a safe string representation (base64) for transport
            let password_b64 = BASE64_STANDARD.encode(&password_bytes[..]);

            HsmResponse::CredentialGenerated {
                credential_id,
                password: password_b64,
                wrapped_password: wrapped,
                key_version,
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

        HsmRequest::GenerateRootCaKey { algorithm } => {
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

            let alg = algorithm.trim().to_string();

            // Only support ECDSA P-256 for now
            if alg != "ECDSA_P256" {
                return HsmResponse::Error {
                    code: 400,
                    message: format!("Unsupported algorithm: {}", alg),
                };
            }

            // Generate ECDSA P-256 keypair inside vHSM using p256 crate
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use rand::rngs::OsRng;

            // Create signing key (private) using secure RNG
            let signing_key = SigningKey::random(&mut OsRng);

            // Extract private scalar as bytes (32 bytes) and keep in Zeroizing
            let private_bytes = signing_key.to_bytes();
            let private_vec = Zeroizing::new(private_bytes.to_vec());

            // Obtain public key as SEC1 encoded uncompressed point
            let verifying_key = signing_key.verifying_key();
            let public_key_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();

            // Encrypt private key bytes with vHSM root/master key using existing AES-GCM helper
            let wrapped = match crypto::encrypt_bytes(root_key.as_ref(), private_vec.as_ref()) {
                Ok(v) => v,
                Err(msg) => {
                    return HsmResponse::Error {
                        code: 500,
                        message: msg,
                    };
                }
            };

            let version = guard.active_key_version;

            // Zeroizing(private_vec) will be dropped and zeroed when out of scope

            HsmResponse::RootCaKeyGenerated {
                encrypted_private_key: wrapped,
                public_key: public_key_sec1,
                master_key_version: version,
                algorithm: alg,
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

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::handler::BASE64_STANDARD;
    use crate::handler::crypto;
    use crate::state::VhsmState;
    use base64::Engine;
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
    async fn generate_root_ca_key_returns_encrypted_only_and_respects_sealed_state() {
        let state = Arc::new(RwLock::new(VhsmState::new()));

        // When sealed -> should return 403
        let resp_sealed = handle_request(
            HsmRequest::GenerateRootCaKey {
                algorithm: "TESTALG".to_string(),
            },
            state.clone(),
        )
        .await;

        match resp_sealed {
            HsmResponse::Error { code, .. } => assert_eq!(code, 403),
            other => panic!("unexpected response when sealed: {other:?}"),
        }

        // Unseal
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 42;
            guard.master_key = Some(Zeroizing::new(vec![3u8; 32]));
        }

        let resp = handle_request(
            HsmRequest::GenerateRootCaKey {
                algorithm: "ECDSA_P256".to_string(),
            },
            state.clone(),
        )
        .await;

        match resp {
            HsmResponse::RootCaKeyGenerated {
                encrypted_private_key,
                public_key,
                master_key_version,
                algorithm,
            } => {
                assert!(!encrypted_private_key.is_empty());
                assert!(!public_key.is_empty());
                assert_eq!(master_key_version, 42);
                assert_eq!(algorithm, "ECDSA_P256");
                // Ensure encrypted payload is not equal to public blob
                assert_ne!(encrypted_private_key, public_key);

                // Now decrypt encrypted_private_key using master key and verify the keypair math
                let guard = state.read().await;
                let root = guard.master_key.as_ref().unwrap();
                let decrypted = crypto::decrypt_bytes(root.as_ref(), &encrypted_private_key)
                    .expect("decrypt should succeed");

                // Reconstruct SigningKey from bytes
                use p256::EncodedPoint;
                use p256::ecdsa::SigningKey;

                // decrypted is Zeroizing<Vec<u8>> -> Vec<u8>
                let sk_vec: &Vec<u8> = decrypted.as_ref();
                let sk_bytes: [u8; 32] = sk_vec
                    .as_slice()
                    .try_into()
                    .expect("private key length must be 32 bytes");

                let signing_key = SigningKey::from_bytes(&sk_bytes).expect("create signing key");

                // Build verifying key and compare to returned public_key
                let verifying_key = signing_key.verifying_key();
                let expected_pub = verifying_key.to_encoded_point(false);
                let got_pub = EncodedPoint::from_bytes(&public_key).expect("parse public key");
                assert_eq!(expected_pub.as_bytes(), got_pub.as_bytes());

                // Test signing and verifying
                use p256::ecdsa::{Signature, signature::Signer, signature::Verifier};
                let msg = b"test message";
                let sig: Signature = signing_key.sign(msg);
                assert!(verifying_key.verify(msg, &sig).is_ok());
            }
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

    #[tokio::test]
    async fn generate_credential_happy_path_and_unwrap() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 11;
            guard.master_key = Some(Zeroizing::new(vec![7u8; 32]));
        }

        let resp = handle_request(
            HsmRequest::GenerateCredential {
                password_length: 32,
            },
            state.clone(),
        )
        .await;

        match resp {
            HsmResponse::CredentialGenerated {
                credential_id,
                password,
                wrapped_password,
                key_version,
            } => {
                assert!(!credential_id.is_empty());
                let pwd_bytes = BASE64_STANDARD.decode(&password).expect("base64 decode");
                assert_eq!(pwd_bytes.len(), 32);
                assert!(!wrapped_password.is_empty());
                assert_eq!(key_version, 11);

                // Ensure wrapped_password is not plaintext
                assert_ne!(wrapped_password, pwd_bytes);

                // Decrypt wrapped_password using master key
                let guard = state.read().await;
                let root = guard.master_key.as_ref().unwrap();
                let decrypted = crypto::decrypt_bytes(root.as_ref(), &wrapped_password)
                    .expect("decrypt should succeed");
                let dec_vec: &Vec<u8> = decrypted.as_ref();
                assert_eq!(dec_vec.as_slice(), pwd_bytes.as_slice());

                // Nonce should be present (first 12 bytes) and non-zero
                assert!(wrapped_password.len() > 12);
                let nonce = &wrapped_password[..12];
                assert!(nonce.iter().any(|b| *b != 0));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn generate_credential_uniqueness_and_locked_rejection() {
        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 4;
            guard.master_key = Some(Zeroizing::new(vec![9u8; 32]));
        }

        let r1 = handle_request(
            HsmRequest::GenerateCredential {
                password_length: 16,
            },
            state.clone(),
        )
        .await;

        let r2 = handle_request(
            HsmRequest::GenerateCredential {
                password_length: 16,
            },
            state.clone(),
        )
        .await;

        let (id1, pwd1) = match r1 {
            HsmResponse::CredentialGenerated {
                credential_id,
                password,
                ..
            } => (credential_id, password),
            other => panic!("unexpected: {other:?}"),
        };

        let (id2, pwd2) = match r2 {
            HsmResponse::CredentialGenerated {
                credential_id,
                password,
                ..
            } => (credential_id, password),
            other => panic!("unexpected: {other:?}"),
        };

        assert_ne!(id1, id2);
        assert_ne!(pwd1, pwd2);

        // Now test locked rejection
        let state_locked = Arc::new(RwLock::new(VhsmState::new()));
        let resp = handle_request(
            HsmRequest::GenerateCredential { password_length: 8 },
            state_locked,
        )
        .await;

        match resp {
            HsmResponse::Error { code, .. } => assert_eq!(code, 403),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn generate_credential_not_logged() {
        use std::io::{self, Write};
        use std::sync::{Arc as StdArc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        // Shared buffer for logs
        let buf = StdArc::new(Mutex::new(Vec::new()));

        struct SharedWriter(StdArc<Mutex<Vec<u8>>>);
        impl<'a> MakeWriter<'a> for SharedWriter {
            type Writer = SharedGuardWriter;
            fn make_writer(&'a self) -> Self::Writer {
                SharedGuardWriter(self.0.clone())
            }
        }

        struct SharedGuardWriter(StdArc<Mutex<Vec<u8>>>);
        impl Write for SharedGuardWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let mut guard = self.0.lock().unwrap();
                guard.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let writer = SharedWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);

        let state = Arc::new(RwLock::new(VhsmState::new()));
        {
            let mut guard = state.write().await;
            guard.initialized = true;
            guard.active_key_version = 2;
            guard.master_key = Some(Zeroizing::new(vec![3u8; 32]));
        }

        let resp = handle_request(
            HsmRequest::GenerateCredential {
                password_length: 12,
            },
            state,
        )
        .await;

        let pwd_b64 = match resp {
            HsmResponse::CredentialGenerated { password, .. } => password,
            other => panic!("unexpected: {other:?}"),
        };

        // Inspect captured logs to ensure password not present
        let logs = buf.lock().unwrap();
        let logs_str = String::from_utf8_lossy(&logs);
        assert!(!logs_str.contains(&pwd_b64));
    }
}
