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

pub struct EncryptDataUseCase<C, A>
where
    C: KmsCryptoService,
    A: crate::domain::audit::repository::AuditRepository,
{
    crypto: Arc<C>,
    audit_service: Arc<AuditService<A>>,
}

impl<C, A> EncryptDataUseCase<C, A>
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
        plaintext: &[u8],
    ) -> AppResult<EncryptedPrivateKey> {
        let result = self.crypto.encrypt_private_key(plaintext).await;
        match &result {
            Ok(data) => {
                self.audit_service
                    .record_success(
                        ctx,
                        AuditAction::EncryptData,
                        Some(json!({
                            "plaintext_length": plaintext.len(),
                            "result": "ok",
                            "master_key_version": data.master_key_version
                        })),
                    )
                    .await?;
                Ok(data.clone())
            }
            Err(err) => {
                self.audit_service
                    .record_failure(ctx, AuditAction::EncryptData, err.to_string())
                    .await?;
                Err(crate::errors::AppError::crypto_error(err.to_string()))
            }
        }
    }
}
