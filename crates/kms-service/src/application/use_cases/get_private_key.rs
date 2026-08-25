// src/application/use_cases/get_private_key.rs
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    config::acl::{CompiledAcl, KeyAccessLevel, authorize_key_access},
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
    server::state::KeyCache,
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
    key_cache: Arc<KeyCache>,
    acl_policy: Arc<CompiledAcl>,
}

impl<R, A> GetPrivateKeyUseCase<R, A>
where
    R: KeyRepository,
    A: AuditRepository,
{
    //#region new
    pub fn new(
        key_repo: Arc<R>,
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        key_cache: Arc<KeyCache>,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            key_cache,
            acl_policy,
        }
    }

    pub async fn execute(&self, input: GetPrivateKeyInput) -> AppResult<GetPrivateKeyOutput> {
        let is_allowed = authorize_key_access(
            &self.acl_policy,
            &input.caller_service,
            &input.target_service,
            input.algorithm,
            KeyAccessLevel::PrivateKey,
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

        if let Some(cached) = self.key_cache.with_key(
            &input.target_service,
            input.algorithm,
            |cached_version, cached_bytes| (cached_version, cached_bytes.to_vec()),
        ) {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::GetPrivateKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::Success,
                    reason: Some("cache_hit".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            let (cached_version, cached_bytes) = cached;
            return Ok(GetPrivateKeyOutput {
                service_id: input.target_service.clone(),
                algorithm: input.algorithm,
                version: cached_version,
                private_key_bytes: cached_bytes,
            });
        }

        // 2. Pobranie klucza z DB (TYLKO Active)
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
            .decrypt_private_key(&active_key.encrypted_private_key)
            .await?;

        let preload_enabled = self
            .acl_policy
            .should_preload_for(&input.target_service, input.algorithm);
        if preload_enabled {
            self.key_cache.insert(
                &input.target_service,
                input.algorithm,
                active_key.version,
                decrypted_private_key.clone(),
            );
        }

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
