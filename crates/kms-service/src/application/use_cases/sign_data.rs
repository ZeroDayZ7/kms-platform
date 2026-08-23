use chrono::Utc;
use ed25519_dalek::Signer;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

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
pub struct SignDataInput {
    pub caller_service: ServiceId,
    pub target_service: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub payload: Vec<u8>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SignDataOutput {
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub key_version: u32,
    pub signature_bytes: Vec<u8>,
}

pub struct SignDataUseCase<R, A>
where
    R: KeyRepository,
    A: AuditRepository,
{
    key_repo: Arc<R>,
    audit_repo: Arc<A>,
    crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
    key_cache: Arc<KeyCache>,
    acl_settings: Arc<AclSettings>,
}

impl<R, A> SignDataUseCase<R, A>
where
    R: KeyRepository,
    A: AuditRepository,
{
    pub fn new(
        key_repo: Arc<R>,
        audit_repo: Arc<A>,
        crypto_service: Arc<dyn KmsCryptoService + Send + Sync>,
        key_cache: Arc<KeyCache>,
        acl_settings: Arc<AclSettings>,
    ) -> Self {
        Self {
            key_repo,
            audit_repo,
            crypto_service,
            key_cache,
            acl_settings,
        }
    }

    pub async fn execute(&self, input: SignDataInput) -> AppResult<SignDataOutput> {
        if input.algorithm != KeyAlgorithm::Ed25519 {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::SignData,
                    algorithm: input.algorithm,
                    status: AuditStatus::Failure,
                    reason: Some("Only Ed25519 signing is supported".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::ValidationError(
                "Signing endpoint supports only Ed25519 keys".to_string(),
            ));
        }

        let is_allowed = self.acl_settings.is_allowed(
            &input.caller_service,
            &input.target_service,
            input.algorithm,
            &KeyAccessLevel::PrivateKey,
        );

        if !is_allowed {
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::SignData,
                    algorithm: input.algorithm,
                    status: AuditStatus::AccessDenied,
                    reason: Some("ACL Policy Violation".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::Unauthorized);
        }

        let mut private_key_bytes = if let Some(cached) =
            self.key_cache
                .with_key(&input.target_service, input.algorithm, |_, bytes| {
                    bytes.to_vec()
                }) {
            cached
        } else {
            let key = match input.key_version {
                Some(version) => {
                    self.key_repo
                        .get_key_by_version(&input.target_service, input.algorithm, version)
                        .await?
                }
                None => {
                    self.key_repo
                        .get_active_key(&input.target_service, input.algorithm)
                        .await?
                }
            };

            let key = match key {
                Some(key) => key,
                None => {
                    self.audit_repo
                        .record(AuditLog {
                            id: Uuid::now_v7(),
                            caller_service: input.caller_service.clone(),
                            target_service: input.target_service.clone(),
                            action: AuditAction::SignData,
                            algorithm: input.algorithm,
                            status: AuditStatus::NotFound,
                            reason: Some("Signing key not found".to_string()),
                            timestamp: Utc::now(),
                        })
                        .await?;

                    return Err(AppError::NotFound("Signing key not found".into()));
                }
            };

            let bytes = match self
                .crypto_service
                .decrypt_private_key(&key.encrypted_private_key)
                .await
            {
                Ok(bytes) => bytes,
                Err(err) => {
                    self.audit_repo
                        .record(AuditLog {
                            id: Uuid::now_v7(),
                            caller_service: input.caller_service.clone(),
                            target_service: input.target_service.clone(),
                            action: AuditAction::SignData,
                            algorithm: input.algorithm,
                            status: AuditStatus::Failure,
                            reason: Some(err.to_string()),
                            timestamp: Utc::now(),
                        })
                        .await?;

                    return Err(err);
                }
            };

            let preload_enabled = self.acl_settings.services.values().any(|service_cfg| {
                service_cfg.allowed_access.iter().any(|rule| {
                    rule.target_service == input.target_service
                        && rule.algorithm == input.algorithm
                        && rule.access_level == KeyAccessLevel::PrivateKey
                        && rule.preload
                })
            });
            if preload_enabled {
                self.key_cache.insert(
                    &input.target_service,
                    input.algorithm,
                    key.version,
                    bytes.clone(),
                );
            }
            bytes
        };

        if private_key_bytes.len() < 32 {
            private_key_bytes.zeroize();
            self.audit_repo
                .record(AuditLog {
                    id: Uuid::now_v7(),
                    caller_service: input.caller_service.clone(),
                    target_service: input.target_service.clone(),
                    action: AuditAction::SignData,
                    algorithm: input.algorithm,
                    status: AuditStatus::Failure,
                    reason: Some("Invalid Ed25519 private key length".to_string()),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::CryptoError(
                "Invalid Ed25519 private key length".to_string(),
            ));
        }

        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&private_key_bytes[..32]);

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key_array);
        let signature = signing_key.sign(&input.payload);

        private_key_array.zeroize();
        private_key_bytes.zeroize();

        let output_target_service = input.target_service.clone();
        let output_version = match input.key_version {
            Some(version) => version,
            None => self
                .key_repo
                .get_active_key(&output_target_service, input.algorithm)
                .await?
                .map(|key| key.version)
                .unwrap_or(0),
        };

        self.audit_repo
            .record(AuditLog {
                id: Uuid::now_v7(),
                caller_service: input.caller_service.clone(),
                target_service: output_target_service.clone(),
                action: AuditAction::SignData,
                algorithm: input.algorithm,
                status: AuditStatus::Success,
                reason: None,
                timestamp: Utc::now(),
            })
            .await?;

        Ok(SignDataOutput {
            service_id: output_target_service,
            algorithm: input.algorithm,
            key_version: output_version,
            signature_bytes: signature.to_bytes().to_vec(),
        })
    }
}
