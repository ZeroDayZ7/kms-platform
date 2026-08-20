use std::sync::Arc;
use ed25519_dalek::{SigningKey, pkcs8::EncodePublicKey};
use pkcs8::LineEnding;
use rand_core::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    domain::crypto::{EncryptedPrivateKey, KmsCryptoService as KmsCryptoServiceTrait, RawKeyPair},
    errors::{AppError, AppResult},
    infrastructure::crypto::vhsm_client::VhsmClient,
};

pub struct VhsmCryptoService {
    client: Arc<VhsmClient>,
}

impl VhsmCryptoService {
    pub fn new(client: Arc<VhsmClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl KmsCryptoServiceTrait for VhsmCryptoService {
    // Generowanie kryptograficznych par kluczy pozostaje w kms-service (czysty algorytm lokalny)
    fn generate_ed25519_keypair(&self) -> AppResult<RawKeyPair> {
        let mut rng = rand::rngs::OsRng;
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
        let rng = rand::rngs::OsRng;
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
        let mut rng = rand::rngs::OsRng;

        rng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| AppError::CryptoError(format!("RNG error: {e}")))?;

        Ok(RawKeyPair {
            public_key_pem: String::new(),
            private_key_bytes: key_bytes.to_vec(),
        })
    }

    // Szyfrowanie klucza prywatnego delegujemy asynchronicznie do vhsm-daemon przez socket
    async fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey> {
        let hex_plain = hex::encode(private_key);
        let ciphertext_hex = self.client.encrypt(&hex_plain).await?;
        
        let ciphertext = hex::decode(ciphertext_hex)
            .map_err(|e| AppError::SerializationError(format!("Błąd dekodowania hex z vHSM: {e}")))?;

        Ok(EncryptedPrivateKey {
            ciphertext,
            nonce: Vec::new(), // vHSM zarządza szyfrowaniem wewnętrznie, nonce nie jest potrzebne w kms-service
            master_key_version: 1,
        })
    }

    // Odszyfrowywanie klucza prywatnego przez socket vHSM
    async fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        let hex_cipher = hex::encode(&encrypted.ciphertext);
        let plaintext_hex = self.client.decrypt(&hex_cipher).await?;

        hex::decode(plaintext_hex)
            .map_err(|e| AppError::SerializationError(format!("Błąd dekodowania odszyfrowanego hex: {e}")))
    }

    fn current_master_key_version(&self) -> i32 {
        1
    }
}