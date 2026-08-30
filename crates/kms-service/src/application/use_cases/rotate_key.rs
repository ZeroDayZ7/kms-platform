// src/application/use_cases/rotate_key.rs
use crate::config::crypto::GracePeriodMinutes;
use chrono::{Duration, Utc};
use std::sync::Arc;

use crate::config::acl::{CompiledAcl, ControlAction, authorize_control_action};
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
    acl_policy: Arc<CompiledAcl>,
}

impl<R, A> RotateKeyUseCase<R, A>
where
    R: KeyRepository + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    //#region new
    pub fn new(
        key_repo: Arc<R>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        audit_repo: Arc<A>,
        key_cache: Arc<KeyCache>,
        grace_period_minutes: GracePeriodMinutes,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            key_repo,
            crypto_service,
            audit_repo,
            key_cache,
            grace_period_minutes,
            acl_policy,
        }
    }

    pub async fn execute(&self, input: RotateKeyInput) -> AppResult<KeyPairEntity> {
        // ACL check: RotateOwnKeys for own service, RotateAllKeys for other services
        let required_action = if input.service_id == input.caller_service {
            ControlAction::RotateOwnKeys
        } else {
            ControlAction::RotateAllKeys
        };

        let allowed =
            authorize_control_action(&self.acl_policy, &input.caller_service, &required_action);

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

        // 2. Generate a new key with incremented version and status Active
        let generated_pair = match input.algorithm {
            KeyAlgorithm::Ed25519 => self.crypto_service.generate_ed25519_keypair()?,
            KeyAlgorithm::X25519 => self.crypto_service.generate_x25519_keypair()?,
            KeyAlgorithm::AES256GCM | KeyAlgorithm::HmacSha256 => {
                self.crypto_service.generate_symmetric_key()?
            }
        };

        let encrypted_private_key = self
            .crypto_service
            .encrypt_private_key(generated_pair.private_key_bytes.as_bytes())
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

        let deprecated_until = match input.reason {
            RotationReason::Scheduled | RotationReason::Manual => {
                Some(Utc::now() + Duration::minutes(*self.grace_period_minutes))
            }
            RotationReason::Compromised => None,
        };

        let rotated = self
            .key_repo
            .rotate_active_key(
                &input.service_id,
                input.algorithm,
                &new_entity,
                deprecated_until,
            )
            .await?;

        if !rotated {
            return Err(AppError::Conflict(
                "Failed to rotate key atomically: concurrent modification or active-key race"
                    .into(),
            ));
        }

        // If compromised or manual deactivation, ensure we atomically remove all cached versions
        match input.reason {
            RotationReason::Compromised => self.key_cache.remove_all_for_service(&input.service_id),
            _ => self.key_cache.remove(&input.service_id, input.algorithm),
        }

        // 5. Audit the rotation
        let audit = AuditLog {
            id: uuid::Uuid::now_v7(),
            caller_service: input.service_id.clone(),
            target_service: input.service_id.clone(),
            action: AuditAction::KeyRotated,
            algorithm: input.algorithm,
            status: AuditStatus::Success,
            reason: AuditLog::sanitize_reason(Some(&format!(
                "{:?}; actor={}",
                input.reason, input.actor_id
            ))),
            request_id: None,
            operation_id: None,
            target_id: Some(input.service_id.0.clone()),
            metadata: Some("key_rotation".to_string()),
            timestamp: Utc::now(),
        };

        self.audit_repo.record(audit).await?;

        Ok(new_entity)
    }
}
