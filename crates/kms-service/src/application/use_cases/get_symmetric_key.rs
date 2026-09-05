use std::sync::Arc;

use serde_json::json;

use crate::{
    config::acl::{CompiledAcl, KeyAccessLevel, authorize_key_access},
    domain::{
        audit::{
            models::{AuditAction, RequestContext},
            service::AuditService,
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
    A: crate::domain::audit::repository::AuditRepository,
{
    key_repo: Arc<K>,
    audit_service: Arc<AuditService<A>>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    key_cache: Arc<KeyCache>,
    acl_policy: Arc<CompiledAcl>,
}

impl<K, A> GetSymmetricKeyUseCase<K, A>
where
    K: KeyRepository,
    A: crate::domain::audit::repository::AuditRepository,
{
    pub fn new(
        key_repo: Arc<K>,
        audit_service: Arc<AuditService<A>>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        key_cache: Arc<KeyCache>,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            key_repo,
            audit_service,
            crypto_service,
            key_cache,
            acl_policy,
        }
    }

    pub async fn execute(
        &self,
        ctx: &RequestContext,
        input: GetSymmetricKeyInput,
    ) -> AppResult<GetSymmetricKeyOutput> {
        let is_allowed = authorize_key_access(
            &self.acl_policy,
            &input.caller_service,
            &input.target_service,
            input.algorithm,
            KeyAccessLevel::SymmetricKey,
        );

        if !is_allowed {
            self.audit_service
                .record_access_denied(
                    ctx,
                    AuditAction::GetSymmetricKey,
                    "ACL Policy Violation for Symmetric Key",
                )
                .await?;

            return Err(AppError::Unauthorized);
        }

        if let Some(cached) = self.key_cache.with_key(
            &input.target_service,
            input.algorithm,
            |cached_version, cached_bytes| (cached_version, cached_bytes.to_vec()),
        ) {
            self.audit_service
                .record_success(
                    ctx,
                    AuditAction::GetSymmetricKey,
                    Some(json!({
                        "cache_hit": true,
                        "target_service": input.target_service.0,
                        "algorithm": input.algorithm
                    })),
                )
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
                self.audit_service
                    .record_validation_failure(
                        ctx,
                        AuditAction::GetSymmetricKey,
                        "Symmetric Key does not exist",
                    )
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

        let preload_enabled = self
            .acl_policy
            .should_preload_for(&input.target_service, input.algorithm);
        if preload_enabled {
            self.key_cache.insert(
                &input.target_service,
                input.algorithm,
                key_entity.version,
                decrypted.clone(),
            );
        }

        self.audit_service
            .record_success(
                ctx,
                AuditAction::GetSymmetricKey,
                Some(json!({
                    "target_service": input.target_service.0,
                    "algorithm": input.algorithm,
                    "version": key_entity.version
                })),
            )
            .await?;

        Ok(GetSymmetricKeyOutput {
            service_id: key_entity.service_id,
            algorithm: key_entity.algorithm,
            version: key_entity.version,
            key_bytes: decrypted,
        })
    }
}
