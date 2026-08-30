use chrono::Utc;
use uuid::Uuid;

use crate::{
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
        },
        crypto::{EncryptedPrivateKey, KmsCryptoService},
        keys::models::KeyAlgorithm,
    },
    errors::AppResult,
};
use std::sync::Arc;

pub struct DecryptDataUseCase<C, A>
where
    C: KmsCryptoService,
    A: AuditRepository,
{
    crypto: Arc<C>,
    audit_repo: Arc<A>,
}

impl<C, A> DecryptDataUseCase<C, A>
where
    C: KmsCryptoService,
    A: AuditRepository,
{
    //#region new
    pub fn new(crypto: Arc<C>, audit_repo: Arc<A>) -> Self {
        Self { crypto, audit_repo }
    }

    pub async fn execute(&self, encrypted: &EncryptedPrivateKey) -> AppResult<Vec<u8>> {
        let result = self.crypto.decrypt_private_key(encrypted).await;
        match &result {
            Ok(data) => {
                self.audit_repo
                    .record(AuditLog {
                        id: Uuid::now_v7(),
                        caller_service: "kms-service".into(),
                        target_service: "kms-service".into(),
                        action: AuditAction::DecryptData,
                        algorithm: KeyAlgorithm::AES256GCM,
                        status: AuditStatus::Success,
                        reason: None,
                        request_id: None,
                        operation_id: None,
                        target_id: None,
                        metadata: Some("decrypt_data".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;
                Ok(data.clone())
            }
            Err(err) => {
                self.audit_repo
                    .record(AuditLog {
                        id: Uuid::now_v7(),
                        caller_service: "kms-service".into(),
                        target_service: "kms-service".into(),
                        action: AuditAction::DecryptData,
                        algorithm: KeyAlgorithm::AES256GCM,
                        status: AuditStatus::Failure,
                        reason: AuditLog::sanitize_reason(Some(&err.to_string())),
                        request_id: None,
                        operation_id: None,
                        target_id: None,
                        metadata: Some("decrypt_data_failure".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;
                Err(crate::errors::AppError::CryptoError(err.to_string()))
            }
        }
    }
}
