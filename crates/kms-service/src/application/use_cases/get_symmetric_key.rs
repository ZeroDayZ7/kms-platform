use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    config::acl::{AclSettings, KeyAccessLevel},
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
        },
        crypto::KmsCryptoService,
        keys::{
            models::{KeyAlgorithm, ServiceId},
            repository::KeyRepository,
        },
    },
    errors::{AppError, AppResult},
};

#[derive(Debug, Clone)]
pub struct GetSymmetricKeyInput {
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Clone)]
pub struct GetSymmetricKeyOutput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub version: u32,
    pub key_bytes: Vec<u8>,
}

pub struct GetSymmetricKeyUseCase<K, A>
where
    K: KeyRepository,
    A: AuditRepository,
{
    key_repo: Arc<K>,
    audit_repo: Arc<A>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    acl: Arc<AclSettings>,
}

impl<K, A> GetSymmetricKeyUseCase<K, A>
where
    K: KeyRepository,
    A: AuditRepository,
{
    pub fn new(
        key_repo: Arc<K>,
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        acl: Arc<AclSettings>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            acl,
        }
    }

    pub async fn execute(&self, input: GetSymmetricKeyInput) -> AppResult<GetSymmetricKeyOutput> {
        let is_allowed = self.acl.is_allowed(
            &input.caller_service,
            &input.target_service,
            input.algorithm,
            &KeyAccessLevel::SymmetricKey,
        );

        // 1. Weryfikacja ACL i audytowanie próby nieautoryzowanego dostępu
        if !is_allowed {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::GetSymmetricKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::AccessDenied,
                    reason: Some("ACL Policy Violation for Symmetric Key".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::Unauthorized);
        }

        // 2. Pobieramy aktywny klucz (TYLKO Active) dla kluczy symetrycznych
        let key_entity = match self
            .key_repo
            .get_active_key(&input.target_service, input.algorithm)
            .await?
        {
            Some(key) => key,
            None => {
                self.audit_repo
                    .record(AuditLog {
                        id: Uuid::now_v7(),
                        caller_service: input.caller_service.clone(),
                        target_service: input.target_service.clone(),
                        action: AuditAction::GetSymmetricKey,
                        algorithm: input.algorithm,
                        status: AuditStatus::NotFound,
                        reason: Some("Symmetric Key does not exist".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;

                return Err(AppError::NotFound(format!(
                    "Brak aktywnego klucza symetrycznego dla {}",
                    input.target_service.0
                )));
            }
        };

        let decrypted = self
            .crypto_service
            .decrypt_private_key(&key_entity.encrypted_private_key)?;

        // 3. Rejestracja udanego odczytu w audycie
        self.audit_repo
            .record(AuditLog {
                id: Uuid::now_v7(),
                caller_service: input.caller_service,
                target_service: input.target_service,
                action: AuditAction::GetSymmetricKey,
                algorithm: input.algorithm,
                status: AuditStatus::Success,
                reason: None,
                timestamp: Utc::now(),
            })
            .await?;

        Ok(GetSymmetricKeyOutput {
            service_id: key_entity.service_id,
            algorithm: key_entity.algorithm,
            version: key_entity.version,
            key_bytes: decrypted,
        })
    }
}
