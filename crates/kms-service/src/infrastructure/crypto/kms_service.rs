use ed25519_dalek::{SigningKey, pkcs8::EncodePublicKey};
use pkcs8::LineEnding;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::Arc;
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

    async fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey> {
        let ciphertext = self.client.encrypt(private_key).await?;

        Ok(EncryptedPrivateKey {
            ciphertext,
            master_key_version: 1,
        })
    }

    async fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        let plaintext = self.client.decrypt(&encrypted.ciphertext).await?;
        Ok(plaintext)
    }

    fn current_master_key_version(&self) -> i32 {
        1
    }
}
