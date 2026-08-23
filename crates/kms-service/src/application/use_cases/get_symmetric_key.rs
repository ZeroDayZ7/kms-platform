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
    server::state::KeyCache,
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
    key_cache: Arc<KeyCache>,
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
        key_cache: Arc<KeyCache>,
        acl: Arc<AclSettings>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            key_cache,
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
                    action: AuditAction::GetSymmetricKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::Success,
                    reason: Some("cache_hit".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            let (cached_version, cached_bytes) = cached;
            return Ok(GetSymmetricKeyOutput {
                service_id: input.target_service.clone(),
                algorithm: input.algorithm,
                version: cached_version,
                key_bytes: cached_bytes,
            });
        }

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
            .decrypt_private_key(&key_entity.encrypted_private_key)
            .await?;

        let preload_enabled = self.acl.services.values().any(|service_cfg| {
            service_cfg.allowed_access.iter().any(|rule| {
                rule.target_service == input.target_service
                    && rule.algorithm == input.algorithm
                    && rule.access_level == KeyAccessLevel::SymmetricKey
                    && rule.preload
            })
        });
        if preload_enabled {
            self.key_cache.insert(
                &input.target_service,
                input.algorithm,
                key_entity.version,
                decrypted.clone(),
            );
        }

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
