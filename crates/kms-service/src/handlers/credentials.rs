use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    domain::crypto::KmsCryptoService,
    errors::{AppError, AppResult},
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

const DEFAULT_CREDENTIAL_ACTION_PREFIX: &str = "kms:credentials:provision";
const DEFAULT_PASSWORD_LEN: usize = 32;

// --- DTOs ---

#[derive(Debug, Deserialize)]
pub struct ProvisionCredentialRequest {
    pub service_id: String,
    pub target_db: String,
    pub target_type: String,
    pub resource: String,
}

impl ProvisionCredentialRequest {
    /// Generyczne budowanie ARN zasobu w formacie standardowym `arn:kms:<target_type>:<resource>`
    pub fn to_arn(&self) -> String {
        format!(
            "arn:kms:{}:{}",
            self.target_type.to_lowercase(),
            self.resource
        )
    }

    /// Generyczne budowanie akcji IAM w formacie `kms:credentials:provision:<target_type>`
    pub fn to_iam_action(&self) -> String {
        format!(
            "{}:{}",
            DEFAULT_CREDENTIAL_ACTION_PREFIX,
            self.target_type.to_lowercase()
        )
    }
}

#[derive(Debug, Serialize)]
pub struct ProvisionCredentialResponse {
    pub credential_id: Uuid,
    pub service_id: String,
    pub target_db: String,
    pub username: String,
    pub password: String,
    pub created_at: String,
}

pub struct GeneratedCredentialBlob {
    pub username: String,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
    pub plaintext_password: Zeroizing<String>,
}

// --- Handler ---

pub async fn provision_credential_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<ProvisionCredentialRequest>,
) -> AppResult<Json<ProvisionCredentialResponse>> {
    // 1. Weryfikacja Polityki IAM (Polityka powinna być trzymana w AppState)
    let action = payload.to_iam_action();
    let resource = payload.to_arn();

    tracing::debug!(
        caller = %caller.0,
        action = %action,
        resource = %resource,
        target_db = %payload.target_db,
        "Processing credential provision request"
    );

    if !state
        .iam_policy
        .is_action_allowed(&caller.0, &action, &resource)
    {
        tracing::warn!(
            caller = %caller.0,
            action = %action,
            resource = %resource,
            "IAM Policy denied provision request"
        );
        return Err(AppError::Forbidden);
    }

    // 2. Pobranie aktywnego KEK (Key Encryption Key) dla uszukiwanego serwisu
    let kek_id = fetch_latest_kek_id(&state.db, &payload.service_id).await?;

    // 3. Generowanie generycznych poświadczeń i szyfrowanie przez vHSM
    let username = build_generic_username(&payload.service_id, &payload.target_db);
    let generated =
        generate_secure_credential(&state.crypto_service, &username, DEFAULT_PASSWORD_LEN).await?;

    let credential_id = Uuid::new_v4();
    let created_at = Utc::now();

    // 4. Utrwalenie poświadczenia w bazie
    insert_db_credential(
        &state.db,
        credential_id,
        &payload.service_id,
        &payload.target_db,
        &generated,
        kek_id,
        created_at,
    )
    .await?;

    // 5. Zapis rekordu audytowego w łańcuchu audit_logs
    insert_audit_log(
        &state.db,
        &caller.0,
        &payload.service_id,
        &action,
        &credential_id,
        created_at,
    )
    .await?;

    // 6. Odpowiedź z jawnym hasłem zamienianym na String w obiekcie JSON i bezpieczne zerowanie
    let response = ProvisionCredentialResponse {
        credential_id,
        service_id: payload.service_id,
        target_db: payload.target_db,
        username: generated.username,
        password: generated.plaintext_password.as_str().to_string(),
        created_at: created_at.to_rfc3339(),
    };

    Ok(Json(response))
}

// --- Standalone Domain & Database Functions ---

/// Czyści identyfikatory do postaci bezpiecznych alfanumerycznych znaków SQL/POSIX
pub fn sanitize_identifier(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect();

    if cleaned.is_empty() {
        "kms".to_string()
    } else {
        cleaned.to_ascii_lowercase()
    }
}

/// Buduje unikalną i czytelną nazwę użytkownika bazy danych
pub fn build_generic_username(service_id: &str, target_db: &str) -> String {
    let suffix = Uuid::new_v4().simple().to_string();
    format!(
        "kms_{}_{}_{}",
        sanitize_identifier(service_id),
        sanitize_identifier(target_db),
        &suffix[..8]
    )
}

/// Generuje losowe, kryptograficznie bezpieczne hasło i szyfruje je w usłudze crypto
pub async fn generate_secure_credential(
    crypto_service: &crate::infrastructure::crypto::kms_service::VhsmCryptoService,
    username: &str,
    password_length: usize,
) -> AppResult<GeneratedCredentialBlob> {
    let raw_password: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(password_length)
        .map(char::from)
        .collect();

    let zeroizable_password = Zeroizing::new(raw_password);

    let encrypted = crypto_service
        .encrypt_private_key(zeroizable_password.as_bytes())
        .await?;

    Ok(GeneratedCredentialBlob {
        username: username.to_string(),
        encrypted_password: encrypted.ciphertext,
        nonce: Vec::new(),
        plaintext_password: zeroizable_password,
    })
}

pub async fn fetch_latest_kek_id(pool: &sqlx::PgPool, service_id: &str) -> AppResult<Option<Uuid>> {
    let kek_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM keys WHERE service_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(kek_id)
}

pub async fn insert_db_credential(
    pool: &sqlx::PgPool,
    id: Uuid,
    service_id: &str,
    target_db: &str,
    blob: &GeneratedCredentialBlob,
    kek_id: Option<Uuid>,
    created_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO db_credentials 
            (id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at)
        VALUES 
            ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(id)
    .bind(service_id)
    .bind(target_db)
    .bind(&blob.username)
    .bind(&blob.encrypted_password)
    .bind(&blob.nonce)
    .bind(kek_id)
    .bind(created_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_audit_log(
    pool: &sqlx::PgPool,
    caller_service: &str,
    target_service: &str,
    action: &str,
    credential_id: &Uuid,
    timestamp: DateTime<Utc>,
) -> AppResult<()> {
    let prev_hash_row: Option<String> =
        sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;

    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let hash = compute_audit_hash(&AuditHashInput {
        id: &credential_id.to_string(),
        caller_service,
        target_service,
        action,
        algorithm: "db-credentials",
        status: "Success",
        reason: Some("credential provisioned"),
        prev_hash,
        timestamp: &timestamp,
    });

    sqlx::query(
        r#"
        INSERT INTO audit_logs 
            (id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at) 
        VALUES 
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(caller_service)
    .bind(target_service)
    .bind(action)
    .bind("db-credentials")
    .bind("Success")
    .bind("credential provisioned")
    .bind(prev_hash)
    .bind(hash)
    .bind(Vec::<u8>::new())
    .bind(timestamp)
    .execute(pool)
    .await?;

    Ok(())
}
