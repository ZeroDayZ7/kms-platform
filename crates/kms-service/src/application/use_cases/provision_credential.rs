use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::errors::AppError;
use crate::server::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionResponse {
    pub username: String,
    pub password: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn provision_credential_use_case(
    state: &AppState,
    caller_service_id: &str,
    target_name: &str,
    requested_role: &str,
) -> Result<ProvisionResponse, AppError> {
    // 1. Sprawdzenie IAM z polityki w memory/json
    state.iam_policy.validate_access(caller_service_id, target_name, requested_role)?;

    // 2. Pobranie z bazy KMS połączenia admina dla wskazanego targetu
    let target = state
        .target_repo
        .find_by_name(target_name)
        .await?
        .ok_or_else(|| AppError::NotFound("Target resource not found".into()))?;

    // 3. Odszyfrowanie conn_string przy użyciu KMS Master Key / vHSM
    let conn_string_bytes = state
        .crypto_service
        .decrypt(&target.connection_url_encrypted)
        .await?;
    let conn_string = String::from_utf8(conn_string_bytes)
        .map_err(|e| AppError::Internal(format!("Invalid connection string UTF-8: {}", e)))?;

    // 4. Dobranie odpowiedniego providera (Postgres / Rabbit / MinIO)
    let provider = state.provider_factory.get(&target.target_type)?;

    // 5. Utworzenie usera w docelowym systemie
    let creds = provider.create_user(&conn_string, requested_role, 3600).await?;

    // 6. Zaszyfrowanie wygenerowanego hasła przed zapisem do DB KMS
    let encrypted_secret = state
        .crypto_service
        .encrypt(creds.secret.as_bytes())
        .await?;

    // 7. Zapis do bazy kms-db oraz Zapis zdarzenia w Audit Chain (z hashem poprzedniego)
    let record = state
        .credentials_repo
        .save(
            caller_service_id,
            target.id,
            &creds.username,
            &encrypted_secret,
            requested_role,
            creds.ttl_seconds,
        )
        .await?;

    state
        .audit_repo
        .log_event(
            caller_service_id,
            "CREDENTIAL_PROVISIONED",
            &format!("Issued temp PG user {} for role {}", creds.username, requested_role),
        )
        .await?;

    // 8. Zwrócenie jawnych danych TYLKO RAZ w odpowiedzi HTTP
    Ok(ProvisionResponse {
        username: creds.username,
        password: creds.secret,
        expires_at: record.expires_at,
    })
}