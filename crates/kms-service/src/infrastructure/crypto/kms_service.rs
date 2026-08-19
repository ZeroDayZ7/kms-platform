use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{SigningKey, pkcs8::EncodePublicKey};
use pkcs8::LineEnding;
use std::{collections::HashMap, path::Path};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    config::crypto::{CryptoSettings, MasterKeyProvider},
    domain::crypto::{EncryptedPrivateKey, KmsCryptoService as KmsCryptoServiceTrait, RawKeyPair},
    errors::{AppError, AppResult},
};

const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub struct KmsCryptoService {
    current_version: i32,
    master_keys: HashMap<i32, [u8; 32]>,
}

impl KmsCryptoService {
    pub fn new(settings: &CryptoSettings) -> AppResult<Self> {
        if settings.provider == MasterKeyProvider::Hsm {
            let socket_path = settings.effective_hsm_socket_path();
            let path = Path::new(&socket_path);

            if !path.exists() {
                return Err(AppError::ConfigError(format!(
                    "HSM provider selected but socket is missing at {}",
                    path.display()
                )));
            }

            if !path.is_file() {
                return Err(AppError::ConfigError(format!(
                    "HSM provider selected but socket path {} is not a file",
                    path.display()
                )));
            }
        }

        let mut master_keys = HashMap::new();

        for (&version, b64_key) in &settings.master_keys {
            let decoded_key = BASE64.decode(&b64_key.0).map_err(|e| {
                AppError::CryptoError(format!(
                    "Invalid Master Key Base64 for version {version}: {e}"
                ))
            })?;

            let key_array: [u8; 32] = decoded_key.try_into().map_err(|_| {
                AppError::CryptoError(format!(
                    "Master key for version {version} must be exactly 32 bytes"
                ))
            })?;

            master_keys.insert(version, key_array);
        }

        if !master_keys.contains_key(&settings.current_master_key_version) {
            return Err(AppError::CryptoError(format!(
                "Current master key version {} is missing from configured master keys",
                settings.current_master_key_version
            )));
        }

        Ok(Self {
            current_version: settings.current_master_key_version,
            master_keys,
        })
    }

    fn get_cipher(&self, version: i32) -> AppResult<Aes256Gcm> {
        let key = self.master_keys.get(&version).ok_or_else(|| {
            AppError::CryptoError(format!(
                "Master key version {version} not found in KMS store"
            ))
        })?;

        Aes256Gcm::new_from_slice(key).map_err(|e| {
            AppError::CryptoError(format!(
                "Cipher initialization error for version {version}: {e}"
            ))
        })
    }
}

impl KmsCryptoServiceTrait for KmsCryptoService {
    fn generate_ed25519_keypair(&self) -> AppResult<RawKeyPair> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| {
                AppError::CryptoError(format!("Failed to encode Ed25519 public key to PEM: {e}"))
            })?;

        Ok(RawKeyPair {
            public_key_pem,
            private_key_bytes: signing_key.to_bytes().to_vec(),
        })
    }

    fn generate_x25519_keypair(&self) -> AppResult<RawKeyPair> {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        let public = X25519PublicKey::from(&secret);

        let public_key_pem = pem::encode(&pem::Pem::new(
            "X25519 PUBLIC KEY",
            public.as_bytes().to_vec(),
        ));

        Ok(RawKeyPair {
            public_key_pem,
            private_key_bytes: secret.to_bytes().to_vec(),
        })
    }

    fn generate_symmetric_key(&self) -> AppResult<RawKeyPair> {
        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng;

        rng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| AppError::CryptoError(format!("RNG error: {e}")))?;

        Ok(RawKeyPair {
            public_key_pem: String::new(),
            private_key_bytes: key_bytes.to_vec(),
        })
    }

    fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = OsRng;

        rng.try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| AppError::CryptoError(format!("RNG error: {e}")))?;

        let cipher = self.get_cipher(self.current_version)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| AppError::CryptoError(format!("Envelope encryption failed: {e}")))?;

        Ok(EncryptedPrivateKey {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            master_key_version: self.current_version,
        })
    }

    fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        if encrypted.nonce.len() != NONCE_LEN {
            return Err(AppError::CryptoError(format!(
                "Invalid nonce length: expected {NONCE_LEN} bytes, got {}",
                encrypted.nonce.len()
            )));
        }

        let cipher = self.get_cipher(encrypted.master_key_version)?;
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let decrypted = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|_| {
                AppError::CryptoError(
                    "Envelope decryption failed: invalid key version, tampered data or wrong secret".into(),
                )
            })?;

        Ok(decrypted)
    }

    fn current_master_key_version(&self) -> i32 {
        self.current_version
    }
}
