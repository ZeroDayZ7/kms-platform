// src/application/use_cases/get_private_key.rs
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

pub struct GetPrivateKeyInput {
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub algorithm: KeyAlgorithm,
}

pub struct GetPrivateKeyOutput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub version: u32,
    pub private_key_bytes: Vec<u8>,
}

pub struct GetPrivateKeyUseCase<R, A> {
    key_repo: Arc<R>,
    audit_repo: Arc<A>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    acl_settings: Arc<AclSettings>,
}

impl<R, A> GetPrivateKeyUseCase<R, A>
where
    R: KeyRepository,
    A: AuditRepository,
{
    pub fn new(
        key_repo: Arc<R>,
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        acl_settings: Arc<AclSettings>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            acl_settings,
        }
    }

    pub async fn execute(&self, input: GetPrivateKeyInput) -> AppResult<GetPrivateKeyOutput> {
        let is_allowed = self.acl_settings.is_allowed(
            &input.caller_service,
            &input.target_service,
            input.algorithm,
            &KeyAccessLevel::PrivateKey,
        );

        // 1. Weryfikacja ACL i logowanie próby nieautoryzowanego dostępu
        if !is_allowed {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::GetPrivateKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::AccessDenied,
                    reason: Some("ACL Policy Violation".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::Unauthorized);
        }

        // 2. Pobranie klucza z MongoDB (TYLKO Active)
        let active_key = match self
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
                        action: AuditAction::GetPrivateKey,
                        algorithm: input.algorithm,
                        status: AuditStatus::NotFound,
                        reason: Some("Key does not exist".to_string()),
                        timestamp: Utc::now(),
                    })
                    .await?;

                return Err(AppError::NotFound("Key not found".into()));
            }
        };

        // 3. Odszyfrowanie klucza prywatnego Master Keyem
        let decrypted_private_key = self
            .crypto_service
            .decrypt_private_key(&active_key.encrypted_private_key)?;

        // 4. Rejestracja udanego odczytu w audycie
        self.audit_repo
            .record(AuditLog {
                id: Uuid::now_v7(),
                caller_service: input.caller_service,
                target_service: input.target_service,
                action: AuditAction::GetPrivateKey,
                algorithm: input.algorithm,
                status: AuditStatus::Success,
                reason: None,
                timestamp: Utc::now(),
            })
            .await?;

        Ok(GetPrivateKeyOutput {
            service_id: active_key.service_id,
            algorithm: active_key.algorithm,
            version: active_key.version,
            private_key_bytes: decrypted_private_key,
        })
    }
}
