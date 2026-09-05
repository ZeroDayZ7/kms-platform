use std::sync::Arc;

use serde_json::json;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, RequestContext},
            service::AuditService,
        },
        crypto::{EncryptedPrivateKey, KmsCryptoService},
    },
    errors::AppResult,
};

pub struct DecryptDataUseCase<C, A>
where
    C: KmsCryptoService,
    A: crate::domain::audit::repository::AuditRepository,
{
    crypto: Arc<C>,
    audit_service: Arc<AuditService<A>>,
}

impl<C, A> DecryptDataUseCase<C, A>
where
    C: KmsCryptoService,
    A: crate::domain::audit::repository::AuditRepository,
{
    pub fn new(crypto: Arc<C>, audit_service: Arc<AuditService<A>>) -> Self {
        Self {
            crypto,
            audit_service,
        }
    }

    pub async fn execute(
        &self,
        ctx: &RequestContext,
        encrypted: &EncryptedPrivateKey,
    ) -> AppResult<Vec<u8>> {
        let result = self.crypto.decrypt_private_key(encrypted).await;
        match &result {
            Ok(data) => {
                self.audit_service
                    .record_success(
                        ctx,
                        AuditAction::DecryptData,
                        Some(json!({
                            "ciphertext_length": encrypted.ciphertext.len(),
                            "master_key_version": encrypted.master_key_version,
                            "result": "ok"
                        })),
                    )
                    .await?;
                Ok(data.clone())
            }
            Err(err) => {
                self.audit_service
                    .record_failure(ctx, AuditAction::DecryptData, err.to_string())
                    .await?;
                Err(crate::errors::AppError::crypto_error(err.to_string()))
            }
        }
    }
}
