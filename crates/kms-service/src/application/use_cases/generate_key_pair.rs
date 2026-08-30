use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    config::acl::{CompiledAcl, ControlAction, authorize_control_action},
    domain::{
        audit::{
            models::{AuditAction, AuditLog, AuditStatus},
            repository::AuditRepository,
        },
        crypto::KmsCryptoService,
        keys::{
            models::{KeyAlgorithm, KeyPairEntity, KeyPurpose, ServiceId},
            repository::KeyRepository,
        },
    },
    errors::{AppError, AppResult},
};

pub struct GenerateKeyPairInput {
    pub caller_service: ServiceId,
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
}

pub struct GenerateKeyPairUseCase<R, A> {
    key_repo: Arc<R>,
    audit_repo: Arc<A>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    acl_policy: Arc<CompiledAcl>,
}

impl<R, A> GenerateKeyPairUseCase<R, A>
where
    R: KeyRepository,
    A: AuditRepository,
{
    //#region new
    pub fn new(
        key_repo: Arc<R>,
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        acl_policy: Arc<CompiledAcl>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            acl_policy,
        }
    }

    pub async fn execute(&self, input: GenerateKeyPairInput) -> AppResult<KeyPairEntity> {
        let has_generate_permission = authorize_control_action(
            &self.acl_policy,
            &input.caller_service,
            &ControlAction::GenerateKeys,
        ) || authorize_control_action(
            &self.acl_policy,
            &input.caller_service,
            &ControlAction::RotateOwnKeys,
        ) || authorize_control_action(
            &self.acl_policy,
            &input.caller_service,
            &ControlAction::RotateAllKeys,
        );

        if !has_generate_permission {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.service_id.clone(),
                    action: AuditAction::GenerateKey,
                    algorithm: input.algorithm,
                    status: AuditStatus::AccessDenied,
                    reason: AuditLog::sanitize_reason(Some("ACL Policy Violation for GenerateKey")),
                    request_id: None,
                    operation_id: None,
                    target_id: Some(input.service_id.0.clone()),
                    metadata: Some("acl_policy_violation".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;
            return Err(AppError::Unauthorized);
        }

        let current_key = self
            .key_repo
            .get_active_key(&input.service_id, input.algorithm)
            .await?;

        let version = match current_key {
            Some(ref key) => {
                self.key_repo
                    .deactivate_keys_for_service(&input.service_id, input.algorithm)
                    .await?;
                key.version + 1
            }
            None => 1,
        };

        let generated_pair = match input.algorithm {
            KeyAlgorithm::Ed25519 => self.crypto_service.generate_ed25519_keypair()?,
            KeyAlgorithm::X25519 => self.crypto_service.generate_x25519_keypair()?,
            KeyAlgorithm::AES256GCM | KeyAlgorithm::HmacSha256 => {
                self.crypto_service.generate_symmetric_key()?
            }
        };

        let public_key_pem = generated_pair.public_key_pem.clone();

        // DODANO: .await
        let encrypted_private_key = self
            .crypto_service
            .encrypt_private_key(generated_pair.private_key_bytes.as_bytes())
            .await?;

        let target_service = input.service_id.clone();
        let entity = KeyPairEntity {
            id: uuid::Uuid::now_v7(),
            service_id: target_service.clone(),
            algorithm: input.algorithm,
            purpose: input.purpose,
            public_key_pem,
            encrypted_private_key,
            version,
            status: crate::domain::keys::models::KeyStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        };

        self.key_repo.save_key(&entity).await?;
        self.audit_repo
            .record(AuditLog {
                id: Uuid::now_v7(),
                caller_service: input.caller_service,
                target_service: target_service.clone(),
                action: AuditAction::GenerateKey,
                algorithm: input.algorithm,
                status: AuditStatus::Success,
                reason: None,
                request_id: None,
                operation_id: None,
                target_id: Some(entity.id.to_string()),
                metadata: Some("key_generated".to_string()),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(entity)
    }
}
