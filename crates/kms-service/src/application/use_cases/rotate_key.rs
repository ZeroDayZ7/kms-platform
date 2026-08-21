// src/application/use_cases/rotate_key.rs
use crate::config::crypto::GracePeriodMinutes;
use chrono::{Duration, Utc};
use std::sync::Arc;

use crate::config::acl::{AclSettings, ControlAction};
use crate::domain::audit::models::{AuditAction, AuditLog, AuditStatus};
use crate::domain::audit::repository::AuditRepository;
use crate::domain::crypto::KmsCryptoService;
use crate::domain::keys::models::{
    KeyAlgorithm, KeyPairEntity, KeyStatus, RotationReason, ServiceId,
};
use crate::domain::keys::repository::KeyRepository;
use crate::errors::{AppError, AppResult};
use crate::server::state::KeyCache;

pub struct RotateKeyInput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub caller_service: ServiceId,
    pub reason: RotationReason,
    pub actor_id: String,
}

pub struct RotateKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    key_repo: Arc<R>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    audit_repo: Arc<A>,
    key_cache: Arc<KeyCache>,
    grace_period_minutes: GracePeriodMinutes,
    acl_settings: Arc<AclSettings>,
}

impl<R, A> RotateKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    pub fn new(
        key_repo: Arc<R>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        audit_repo: Arc<A>,
        key_cache: Arc<KeyCache>,
        grace_period_minutes: GracePeriodMinutes,
        acl_settings: Arc<AclSettings>,
    ) -> Self {
        Self {
            key_repo,
            crypto_service,
            audit_repo,
            key_cache,
            grace_period_minutes,
            acl_settings,
        }
    }

    pub async fn execute(&self, input: RotateKeyInput) -> AppResult<KeyPairEntity> {
        // ACL check: RotateOwnKeys for own service, RotateAllKeys for other services
        let required_action = if input.service_id == input.caller_service {
            ControlAction::RotateOwnKeys
        } else {
            ControlAction::RotateAllKeys
        };

        let caller_cfg = self
            .acl_settings
            .services
            .get(&input.caller_service.0)
            .ok_or_else(|| AppError::Unauthorized)?;

        let allowed = caller_cfg
            .allowed_actions
            .as_ref()
            .map(|v| v.contains(&required_action))
            .unwrap_or(false);

        if !allowed {
            return Err(AppError::Unauthorized);
        }

        // 1. Fetch current active key
        let active_key = self
            .key_repo
            .get_active_key(&input.service_id, input.algorithm)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Cannot rotate key: No active key exists for service '{}' with algorithm '{:?}'",
                    input.service_id.0, input.algorithm
                ))
            })?;

        // 2. Update old key status according to reason
        match input.reason {
            RotationReason::Scheduled | RotationReason::Manual => {
                let valid_until = Utc::now() + Duration::minutes(*self.grace_period_minutes);
                let ok = self
                    .key_repo
                    .compare_and_set_active_to_deprecated(&active_key.id, valid_until)
                    .await?;
                if !ok {
                    return Err(AppError::Conflict(
                        "Failed to deprecate key: concurrent modification".into(),
                    ));
                }
            }
            RotationReason::Compromised => {
                // For compromised we don't require CAS; just mark compromised
                self.key_repo
                    .update_key_status(&active_key.id, KeyStatus::Compromised, None)
                    .await?;
            }
        }

        // 3. Generate a new key with incremented version and status Active
        let generated_pair = match input.algorithm {
            KeyAlgorithm::Ed25519 => self.crypto_service.generate_ed25519_keypair()?,
            KeyAlgorithm::X25519 => self.crypto_service.generate_x25519_keypair()?,
            KeyAlgorithm::AES256GCM | KeyAlgorithm::HmacSha256 => {
                self.crypto_service.generate_symmetric_key()?
            }
        };

        let encrypted_private_key = self
            .crypto_service
            .encrypt_private_key(&generated_pair.private_key_bytes)
            .await?;

        let new_entity = KeyPairEntity {
            id: uuid::Uuid::now_v7(),
            service_id: input.service_id.clone(),
            algorithm: input.algorithm,
            purpose: active_key.purpose,
            public_key_pem: generated_pair.public_key_pem.clone(),
            encrypted_private_key,
            version: active_key.version + 1,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        };

        // 4. Persist new key
        self.key_repo.save_key(&new_entity).await?;

        self.key_cache.remove(&input.service_id, input.algorithm);

        // 5. Audit the rotation
        let audit = AuditLog {
            id: uuid::Uuid::now_v7(),
            caller_service: input.service_id.clone(),
            target_service: input.service_id.clone(),
            action: AuditAction::KeyRotated,
            algorithm: input.algorithm,
            status: AuditStatus::Success,
            reason: Some(format!("{:?}; actor={}", input.reason, input.actor_id)),
            timestamp: Utc::now(),
        };

        self.audit_repo.record(audit).await?;

        Ok(new_entity)
    }
}
