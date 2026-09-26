use std::sync::Arc;

use serde_json::json;

use crate::{
    config::acl::{ControlAction, authorize_control_action},
    domain::{
        audit::{
            models::{AuditAction, RequestContext},
            service::AuditService,
        },
        keys::models::ServiceId,
    },
    errors::{AppError, AppResult},
    server::state::AppState,
};

#[derive(Debug, Clone)]
pub struct SignIntermediateCaInput {
    pub caller_service: ServiceId,
    pub ca_tag: String,
    pub csr_pem: String,
    pub validity_days: u32,
}

#[derive(Debug, Clone)]
pub struct SignIntermediateCaOutput {
    pub certificate_pem: String,
}

pub struct SignIntermediateCaUseCase<A>
where
    A: crate::domain::audit::repository::AuditRepository,
{
    audit_service: Arc<AuditService<A>>,
}

impl<A> SignIntermediateCaUseCase<A>
where
    A: crate::domain::audit::repository::AuditRepository,
{
    pub fn new(audit_service: Arc<AuditService<A>>) -> Self {
        Self { audit_service }
    }

    pub async fn execute(
        &self,
        state: &AppState,
        input: SignIntermediateCaInput,
    ) -> AppResult<SignIntermediateCaOutput> {
        let caller = &input.caller_service;

        if !authorize_control_action(
            &state.settings.acl.compile(),
            caller,
            &ControlAction::CaSignIntermediate,
        ) {
            self.audit_service
                .record_access_denied(
                    &RequestContext {
                        operation_id: uuid::Uuid::now_v7().to_string(),
                        nonce: None,
                        actor_id: caller.clone(),
                        ip: None,
                        user_agent: None,
                    },
                    AuditAction::CaSignIntermediate,
                    "ACL policy violation for CA_SIGN_INTERMEDIATE",
                )
                .await?;

            return Err(AppError::Forbidden);
        }

        let req = kms_core::hsm::protocol::HsmRequest::SignIntermediateCa {
            ca_tag: input.ca_tag.clone(),
            csr_pem: input.csr_pem.clone(),
            validity_days: input.validity_days,
        };

        let response = crate::hsm::client::send_hsm_request(
            &state.settings.crypto.hsm_socket_path,
            &req,
            None,
        )
        .await?;

        match response {
            kms_core::hsm::protocol::HsmResponse::SignedIntermediate { certificate_pem } => {
                self.audit_service
                    .record_success(
                        &RequestContext {
                            operation_id: uuid::Uuid::now_v7().to_string(),
                            nonce: None,
                            actor_id: caller.clone(),
                            ip: None,
                            user_agent: None,
                        },
                        AuditAction::CaSignIntermediate,
                        Some(json!({
                            "ca_tag": input.ca_tag,
                            "validity_days": input.validity_days,
                            "csr_pem_len": input.csr_pem.len(),
                            "certificate_pem_len": certificate_pem.len(),
                        })),
                    )
                    .await?;

                Ok(SignIntermediateCaOutput { certificate_pem })
            }
            kms_core::hsm::protocol::HsmResponse::Error { code, message } => {
                self.audit_service
                    .record_failure(
                        &RequestContext {
                            operation_id: uuid::Uuid::now_v7().to_string(),
                            nonce: None,
                            actor_id: caller.clone(),
                            ip: None,
                            user_agent: None,
                        },
                        AuditAction::CaSignIntermediate,
                        format!("HSM error {code}: {message}"),
                    )
                    .await?;

                Err(AppError::CryptoError(format!("HSM error {code}: {message}"), None))
            }
            other => {
                let detail = format!("Unexpected HSM response: {other:?}");
                self.audit_service
                    .record_failure(
                        &RequestContext {
                            operation_id: uuid::Uuid::now_v7().to_string(),
                            nonce: None,
                            actor_id: caller.clone(),
                            ip: None,
                            user_agent: None,
                        },
                        AuditAction::CaSignIntermediate,
                        detail.clone(),
                    )
                    .await?;

                Err(AppError::ValidationError(detail))
            }
        }
    }
}
