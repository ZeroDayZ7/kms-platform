use ed25519_dalek::{SigningKey, pkcs8::EncodePublicKey};
use pkcs8::LineEnding;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    domain::crypto::{
        EncryptedPrivateKey, GeneratedDataKey, KeyAlgorithm,
        KmsCryptoService as KmsCryptoServiceTrait, RawKeyPair, SecretBytes,
    },
    errors::{AppError, AppResult},
    infrastructure::crypto::vhsm_client::VhsmClient,
};

pub struct VhsmCryptoService {
    client: Arc<VhsmClient>,
}

impl VhsmCryptoService {
    //#region new
    pub fn new(client: Arc<VhsmClient>) -> Self {
        Self { client }
    }

    pub async fn generate_credential(
        &self,
        password_length: usize,
    ) -> AppResult<(String, String, Vec<u8>, i32)> {
        let (credential_id, password_b64, wrapped, key_version) =
            self.client.generate_credential(password_length).await?;
        Ok((credential_id, password_b64, wrapped, key_version as i32))
    }
}

#[async_trait::async_trait]
impl KmsCryptoServiceTrait for VhsmCryptoService {
    //#region generate_ed25519_keypair
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
            private_key_bytes: SecretBytes::new(signing_key.to_bytes().to_vec()),
        })
    }

    //#region generate_x25519_keypair
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
            private_key_bytes: SecretBytes::new(secret.to_bytes().to_vec()),
        })
    }

    //#region generate_symmetric_key
    fn generate_symmetric_key(&self) -> AppResult<RawKeyPair> {
        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng;

        rng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| AppError::CryptoError(format!("RNG error: {e}")))?;

        Ok(RawKeyPair {
            public_key_pem: String::new(),
            private_key_bytes: SecretBytes::new(key_bytes.to_vec()),
        })
    }

    async fn generate_data_key(&self, algorithm: KeyAlgorithm) -> AppResult<GeneratedDataKey> {
        if algorithm != KeyAlgorithm::AES256GCM {
            return Err(AppError::ValidationError(
                "Only AES256GCM is supported for GenerateDataKey".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| AppError::CryptoError(format!("RNG error: {e}")))?;

        let plaintext = SecretBytes::new(key_bytes.to_vec());
        let wrapped = self.client.encrypt(plaintext.as_bytes()).await?;
        let version = self.current_master_key_version().await?;

        Ok(GeneratedDataKey {
            algorithm,
            plaintext,
            wrapped,
            master_key_version: version,
        })
    }

    async fn encrypt_private_key(&self, private_key: &[u8]) -> AppResult<EncryptedPrivateKey> {
        let ciphertext = self.client.encrypt(private_key).await?;

        Ok(EncryptedPrivateKey {
            ciphertext,
            master_key_version: self.current_master_key_version().await?,
        })
    }

    async fn decrypt_private_key(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        let plaintext = self.client.decrypt(&encrypted.ciphertext).await?;
        Ok(plaintext)
    }

    //#region current_master_key_version
    async fn current_master_key_version(&self) -> AppResult<i32> {
        let version = self.client.status().await?;
        Ok(version as i32)
    }
}
