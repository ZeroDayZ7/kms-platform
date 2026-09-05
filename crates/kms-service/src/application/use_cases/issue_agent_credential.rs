use chrono::{DateTime, Utc};
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use kms_db::{
    Postgres, Transaction,
    repositories::{AuditQueries, CredentialQueries},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::{AppError, AppResult},
    server::state::AppState,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

pub const DEFAULT_PASSWORD_LEN: usize = 32;

pub struct GeneratedCredentialBlob {
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub plaintext_password: zeroize::Zeroizing<String>,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct IssueAgentCredentialInput {
    pub caller_service: String,
    pub target_service: String,
    pub target_type: String,
    pub resource: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvisioningStatus {
    Pending,
    Provisioning,
    Active,
    Failed,
    Revoking,
}

impl ProvisioningStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Provisioning => "PROVISIONING",
            Self::Active => "ACTIVE",
            Self::Failed => "FAILED",
            Self::Revoking => "REVOKING",
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Provisioning)
                | (Self::Provisioning, Self::Active)
                | (Self::Provisioning, Self::Failed)
                | (Self::Active, Self::Revoking)
                | (Self::Failed, Self::Revoking)
        )
    }
}

#[derive(Debug, Serialize)]
pub struct IssueAgentCredentialOutput {
    pub credential_id: Uuid,
    pub username: String,
    pub password: String,
    pub expires_at: DateTime<Utc>,
}

pub struct IssueAgentCredentialUseCase;

pub fn build_resource_arn(target_type: &str, resource: &str) -> String {
    let target_type_clean = target_type.trim();
    let resource_trimmed = resource.trim();

    if resource_trimmed.starts_with("arn:") {
        return resource_trimmed.to_string();
    }

    format!(
        "arn:kms:{}:{}",
        target_type_clean.to_lowercase(),
        resource_trimmed
    )
}

pub fn validate_agent_credential_acl(
    policy: &crate::config::iam_json::IamCredentialPolicy,
    caller_service: &str,
    target_type: &str,
    resource: &str,
) -> AppResult<()> {
    let target_type_clean = target_type.trim().to_lowercase();
    let action = format!("kms:credentials:provision:{target_type_clean}");
    let resource_arn = build_resource_arn(target_type, resource);

    if !policy.is_action_allowed(caller_service, &action, &resource_arn) {
        tracing::warn!(
            caller = %caller_service,
            action = %action,
            resource = %resource_arn,
            "IAM Policy access denied for agent request"
        );
        return Err(AppError::Forbidden);
    }

    Ok(())
}

impl IssueAgentCredentialUseCase {
    pub fn validate_acl(state: &AppState, input: &IssueAgentCredentialInput) -> AppResult<()> {
        validate_agent_credential_acl(
            &state.iam_policy,
            &input.caller_service,
            &input.target_type,
            &input.resource,
        )
    }

    pub fn validate_batch_acl(
        state: &AppState,
        inputs: &[IssueAgentCredentialInput],
    ) -> AppResult<()> {
        for input in inputs {
            Self::validate_acl(state, input)?;
        }
        Ok(())
    }

    pub async fn execute(
        state: &AppState,
        input: IssueAgentCredentialInput,
    ) -> AppResult<IssueAgentCredentialOutput> {
        let target_type_clean = input.target_type.to_lowercase();
        let action = format!("kms:credentials:provision:{target_type_clean}");

        Self::validate_acl(state, &input)?;

        // 2. Generowanie poświadczeń przez vHSM
        let kek_id = fetch_latest_kek_id(&state.db, "kms-system")
            .await
            .map_err(|err| {
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;
        let username = build_generic_username(&input.caller_service, &input.target_service);
        let generated = generate_secure_credential(
            &state.crypto_service,
            Some(kek_id),
            &username,
            DEFAULT_PASSWORD_LEN,
        )
        .await?;

        // 3. Pobranie connection string admina dla docelowej bazy
        let target_row: Option<(Uuid, Vec<u8>)> =
            CredentialQueries::fetch_target_resource(&state.db, &input.target_service)
                .await
                .map_err(|err| {
                    AppError::database_error_with_source(
                        format!("Database operation failed: {err}"),
                        err,
                    )
                })?;

        let (target_id, conn_encrypted) = match target_row {
            Some(v) => v,
            None => {
                return Err(AppError::NotFound(format!(
                    "Target resource not found: {}",
                    input.target_service
                )));
            }
        };

        let admin_conn_bytes = state
            .crypto_service
            .decrypt_bytes(&conn_encrypted)
            .await
            .map_err(|e| {
                AppError::crypto_error_with_source(
                    format!("Failed to decrypt target connection string: {e}"),
                    e,
                )
            })?;
        let admin_conn = String::from_utf8(admin_conn_bytes).map_err(|_| {
            AppError::crypto_error("Decrypted target connection string is not valid UTF-8")
        })?;

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(input.ttl_seconds as i64);

        // 4. Rozpoczęcie transakcji SQL w KMS
        let mut tx: Transaction<'_, Postgres> = state.db.begin().await.map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;
        // 4.1 Unieważnienie starych, aktywnych poświadczeń dla tego caller
        CredentialQueries::revoke_active_credentials_for_target(
            &mut tx,
            &input.caller_service,
            target_id,
        )
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

        // 5. Zapis pośredniego rekordu lifecycle do KMS przed utworzeniem konta zewnętrznego
        insert_provisioned_credential_tx(
            &mut tx,
            generated.credential_id,
            &input.caller_service,
            target_id,
            &username,
            &generated.encrypted_password,
            &username,
            expires_at,
            ProvisioningStatus::Provisioning.as_str(),
        )
        .await?;

        // 6. Utworzenie użytkownika bezpośrednio u target providera (np. Postgres)
        let provider = state.provider_factory.get(&target_type_clean)?;

        let secret_bytes = BASE64
            .decode(generated.plaintext_password.as_str())
            .map_err(|e| {
                AppError::ValidationError(format!("Invalid base64 password from vHSM: {e}"))
            })?;
        let secret_zero = zeroize::Zeroizing::new(secret_bytes);

        let provider_result = provider
            .create_user(
                &admin_conn,
                &username,
                input.ttl_seconds as i64,
                Some(secret_zero.as_ref()),
            )
            .await;

        drop(secret_zero);

        let provider_credential = match provider_result {
            Ok(c) => c,
            Err(e) => {
                let _ = update_provisioned_credential_status_tx(
                    &mut tx,
                    generated.credential_id,
                    ProvisioningStatus::Failed.as_str(),
                )
                .await;
                let _ = tx.rollback().await;
                return Err(e);
            }
        };

        // 7. Zaaktualizowanie statusu po uzyskaniu aktywnego konta w target providera
        update_provisioned_credential_status_tx(
            &mut tx,
            generated.credential_id,
            ProvisioningStatus::Active.as_str(),
        )
        .await?;

        // 8. Zapis wpisu audytowego
        insert_audit_log_tx(
            &mut tx,
            &input.caller_service,
            &input.target_service,
            &action,
            &generated.credential_id,
            created_at,
        )
        .await?;

        // 9. Zatwierdzenie transakcji
        if let Err(commit_err) = tx.commit().await {
            let _ = provider
                .revoke_user(&admin_conn, &provider_credential.username)
                .await;
            return Err(AppError::Internal(format!(
                "DB commit failed: {commit_err}"
            )));
        }

        Ok(IssueAgentCredentialOutput {
            credential_id: generated.credential_id,
            username: provider_credential.username,
            password: generated.plaintext_password.as_str().to_string(),
            expires_at,
        })
    }
}

// --- Funkcje pomocnicze ---

pub fn build_generic_username(caller_service: &str, target_service: &str) -> String {
    format!("kms_{}_{}", caller_service, target_service)
}

pub async fn fetch_latest_kek_id(db: &kms_db::PgPool, target_service_id: &str) -> AppResult<Uuid> {
    let kek_id = CredentialQueries::fetch_latest_kek_id(db, target_service_id)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?
        .ok_or_else(|| {
            AppError::KeyNotFound(format!(
                "No active AES256GCM KEK found for {}",
                target_service_id
            ))
        })?;

    Ok(kek_id)
}

pub async fn generate_secure_credential(
    crypto_service: &crate::infrastructure::crypto::kms_service::VhsmCryptoService,
    kek_id: Option<Uuid>,
    username: &str,
    length: usize,
) -> AppResult<GeneratedCredentialBlob> {
    let _key_id =
        kek_id.ok_or_else(|| AppError::Internal("No active KEK found for encryption".into()))?;

    let (credential_id, password_b64, wrapped_password, _key_version) = crypto_service
        .generate_credential(length)
        .await
        .map_err(|e| {
            AppError::crypto_error_with_source(
                format!("Failed to generate credential via vHSM: {e}"),
                e,
            )
        })?;

    if wrapped_password.len() < 12 {
        return Err(AppError::crypto_error(
            "Wrapped password payload too short (missing nonce)",
        ));
    }
    let nonce = wrapped_password[..12].to_vec();

    let id_bytes = hex::decode(&credential_id)
        .map_err(|_| AppError::crypto_error("Invalid credential id format from vHSM"))?;
    if id_bytes.len() != 16 {
        return Err(AppError::crypto_error(
            "Credential id from vHSM has invalid length",
        ));
    }
    let uuid = Uuid::from_slice(&id_bytes)
        .map_err(|_| AppError::crypto_error("Failed to parse credential id into UUID"))?;

    Ok(GeneratedCredentialBlob {
        credential_id: uuid,
        username: username.to_string(),
        plaintext_password: zeroize::Zeroizing::new(password_b64),
        encrypted_password: wrapped_password,
        nonce,
    })
}

// --- Funkcje pomocnicze transakcyjne ---

#[allow(clippy::too_many_arguments)]
pub async fn insert_provisioned_credential_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    service_id: &str,
    target_id: Uuid,
    username: &str,
    password_encrypted: &[u8],
    granted_role: &str,
    expires_at: DateTime<Utc>,
    status: &str,
) -> AppResult<()> {
    CredentialQueries::insert_provisioned_credential(
        tx,
        id,
        service_id,
        target_id,
        username,
        password_encrypted,
        granted_role,
        expires_at,
        status,
    )
    .await
    .map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    Ok(())
}

pub async fn update_provisioned_credential_status_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    status: &str,
) -> AppResult<()> {
    CredentialQueries::update_provisioned_credential_status(tx, id, status)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    Ok(())
}

pub async fn insert_audit_log_tx(
    tx: &mut Transaction<'_, Postgres>,
    caller_service: &str,
    target_service: &str,
    action: &str,
    credential_id: &Uuid,
    timestamp: DateTime<Utc>,
) -> AppResult<()> {
    let prev_hash_row: Option<String> = AuditQueries::latest_hash_tx(tx).await.map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let hash = compute_audit_hash(&AuditHashInput {
        id: &credential_id.to_string(),
        caller_service,
        target_service,
        action,
        algorithm: "db-credentials",
        status: "Success",
        reason: Some("agent credential provisioned"),
        prev_hash,
        timestamp: &timestamp,
        request_id: None,
        operation_id: None,
        target_id: Some(&credential_id.to_string()),
        metadata: Some("credential_provisioned"),
        hash_version: kms_core::audit::CURRENT_AUDIT_HASH_VERSION,
    });

    AuditQueries::insert_tx(
        tx,
        kms_db::repositories::AuditInsert {
            id: Uuid::new_v4(),
            caller_service: caller_service.to_string(),
            target_service: target_service.to_string(),
            action: action.to_string(),
            algorithm: "db-credentials".to_string(),
            status: "Success".to_string(),
            reason: Some("agent credential provisioned".to_string()),
            prev_hash: prev_hash.to_string(),
            hash,
            signature: Some(Vec::<u8>::new()),
            request_id: None,
            operation_id: None,
            target_id: Some(credential_id.to_string()),
            metadata: Some("credential_provisioned".to_string()),
            created_at: timestamp,
        },
    )
    .await
    .map_err(|err| {
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_status_transitions_are_explicit_and_safe() {
        assert_eq!(ProvisioningStatus::Pending.as_str(), "PENDING");
        assert_eq!(ProvisioningStatus::Provisioning.as_str(), "PROVISIONING");
        assert_eq!(ProvisioningStatus::Active.as_str(), "ACTIVE");
        assert_eq!(ProvisioningStatus::Failed.as_str(), "FAILED");
        assert_eq!(ProvisioningStatus::Revoking.as_str(), "REVOKING");

        assert!(ProvisioningStatus::Pending.can_transition_to(ProvisioningStatus::Provisioning));
        assert!(ProvisioningStatus::Provisioning.can_transition_to(ProvisioningStatus::Active));
        assert!(ProvisioningStatus::Active.can_transition_to(ProvisioningStatus::Revoking));
        assert!(!ProvisioningStatus::Active.can_transition_to(ProvisioningStatus::Provisioning));
    }

    #[test]
    fn validate_batch_acl_fails_fast_for_unauthorized_item() {
        let policy = crate::config::iam_json::IamCredentialPolicy {
            version: "test".to_string(),
            statements: vec![crate::config::iam_json::IamStatement {
                sid: "allow-db-auth".to_string(),
                effect: "Allow".to_string(),
                roles: vec!["auth-service".to_string()],
                actions: vec!["kms:credentials:provision:database".to_string()],
                resources: vec!["arn:kms:database:auth_db".to_string()],
            }],
        };

        let valid_result =
            validate_agent_credential_acl(&policy, "auth-service", "database", "auth_db");
        assert!(valid_result.is_ok());

        let unauthorized_result =
            validate_agent_credential_acl(&policy, "auth-service", "database", "other_db");
        assert!(matches!(unauthorized_result, Err(AppError::Forbidden)));
    }
}
