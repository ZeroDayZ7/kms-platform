use crate::domain::crypto::{EncryptedPrivateKey, KmsCryptoService};
use crate::errors::AppResult;
use std::sync::Arc;

pub struct DecryptDataUseCase<C>
where
    C: KmsCryptoService,
{
    crypto: Arc<C>,
}

impl<C> DecryptDataUseCase<C>
where
    C: KmsCryptoService,
{
    pub fn new(crypto: Arc<C>) -> Self {
        Self { crypto }
    }

    pub fn execute(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        self.crypto.decrypt_private_key(encrypted)
    }
}
