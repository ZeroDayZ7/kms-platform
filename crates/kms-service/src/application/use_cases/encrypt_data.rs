use crate::domain::crypto::{EncryptedPrivateKey, KmsCryptoService};
use crate::errors::AppResult;
use std::sync::Arc;

pub struct EncryptDataUseCase<C>
where
    C: KmsCryptoService,
{
    crypto: Arc<C>,
}

impl<C> EncryptDataUseCase<C>
where
    C: KmsCryptoService,
{
    pub fn new(crypto: Arc<C>) -> Self {
        Self { crypto }
    }

    pub async fn execute(&self, plaintext: &[u8]) -> AppResult<EncryptedPrivateKey> {
        self.crypto.encrypt_private_key(plaintext).await
    }
}
