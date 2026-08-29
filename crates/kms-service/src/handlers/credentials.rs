use axum::{Json, extract::State};
use chrono::Utc;
use kms_core::audit::{AuditHashInput, compute_audit_hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    config::iam_json::IamCredentialPolicy,
    domain::crypto::KmsCryptoService,
    errors::{AppError, AppResult},
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

const IAM_CREDENTIAL_ACTION: &str = "kms:credentials:provision";
const IAM_CREDENTIAL_ACTION_POSTGRES: &str = "kms:credentials:provision:postgres";
const IAM_CREDENTIAL_ACTION_MINIO: &str = "kms:credentials:provision:minio";
const IAM_CREDENTIAL_ACTION_RABBITMQ: &str = "kms:credentials:provision:rabbitmq";

#[derive(Debug, Deserialize)]
pub struct ProvisionCredentialRequest {
    pub service_id: String,
    pub target_db: String,
    pub target_type: String,
    pub resource: String,
}

#[derive(Debug, Serialize)]
pub struct ProvisionCredentialResponse {
    pub credential_id: String,
    pub service_id: String,
    pub target_db: String,
    pub username: String,
    pub password: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedCredentialBlob {
    pub username: String,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
    pub plaintext_password: String,
}

fn sanitize_identifier(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("kms");
    }
    out.to_ascii_lowercase()
}

fn build_username(service_id: &str, target_db: &str) -> String {
    let suffix = Uuid::new_v4().simple().to_string();
    format!(
        "kms_{}_{}_{}",
        sanitize_identifier(service_id),
        sanitize_identifier(target_db),
        &suffix[..12]
    )
}

async fn resolve_kek_id(pool: &sqlx::PgPool, service_id: &str) -> AppResult<Option<Uuid>> {
    let value = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM keys WHERE service_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;
    Ok(value)
}

async fn append_audit_record(
    pool: &sqlx::PgPool,
    caller_service: &str,
    target_service: &str,
    _target_db: &str,
    credential_id: &Uuid,
    _username: &str,
) -> AppResult<()> {
    let prev_hash_row: Option<String> =
        sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;

    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    let timestamp = Utc::now();
    let hash = compute_audit_hash(&AuditHashInput {
        id: &credential_id.to_string(),
        caller_service,
        target_service,
        action: IAM_CREDENTIAL_ACTION,
        algorithm: "db-credentials",
        status: "Success",
        reason: Some("credential provisioned"),
        prev_hash,
        timestamp: &timestamp,
    });

    sqlx::query(
        "INSERT INTO audit_logs (id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::new_v4())
    .bind(caller_service)
    .bind(target_service)
    .bind(IAM_CREDENTIAL_ACTION)
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

async fn generate_vhsm_credential(
    vhsm: &crate::infrastructure::crypto::kms_service::VhsmCryptoService,
    _kek_id: Option<Uuid>,
    username: &str,
    service_id: &str,
    target_db: &str,
) -> AppResult<GeneratedCredentialBlob> {
    let secret_material = format!("{service_id}:{target_db}:{username}");
    let encrypted = vhsm.encrypt_private_key(secret_material.as_bytes()).await?;
    let password = hex::encode(&encrypted.ciphertext);

    Ok(GeneratedCredentialBlob {
        username: username.to_string(),
        encrypted_password: encrypted.ciphertext.clone(),
        nonce: Vec::new(),
        plaintext_password: password,
    })
}

pub async fn provision_credential_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<ProvisionCredentialRequest>,
) -> AppResult<Json<ProvisionCredentialResponse>> {
    let policy = IamCredentialPolicy::load_default()
        .map_err(|err| AppError::ConfigError(format!("Failed to process IAM policy: {err}")))?;

    let resource = match payload.target_type.as_str() {
        "postgres" => format!("arn:kms:postgres:{}", payload.resource),
        "minio" => format!("arn:kms:minio:{}", payload.resource),
        "rabbitmq" => format!("arn:kms:rabbitmq:{}", payload.resource),
        _ => format!("arn:kms:{}:{}", payload.target_type, payload.resource),
    };

    let action = match payload.target_type.as_str() {
        "postgres" => IAM_CREDENTIAL_ACTION_POSTGRES,
        "minio" => IAM_CREDENTIAL_ACTION_MINIO,
        "rabbitmq" => IAM_CREDENTIAL_ACTION_RABBITMQ,
        _ => IAM_CREDENTIAL_ACTION,
    };

    if !policy.is_action_allowed(&caller.0, action, &resource) {
        return Err(AppError::Forbidden);
    }

    let credential_id = Uuid::new_v4();
    let username = build_username(&payload.service_id, &payload.target_db);
    let created_at = Utc::now();
    let kek_id = resolve_kek_id(&state.db, &payload.service_id).await?;

    let generated = generate_vhsm_credential(
        &state.crypto_service,
        kek_id,
        &username,
        &payload.service_id,
        &payload.target_db,
    )
    .await?;

    sqlx::query(
        "INSERT INTO db_credentials (id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(credential_id)
    .bind(&payload.service_id)
    .bind(&payload.target_db)
    .bind(&generated.username)
    .bind(&generated.encrypted_password)
    .bind(&generated.nonce)
    .bind(kek_id)
    .bind(created_at)
    .execute(&state.db)
    .await?;

    append_audit_record(
        &state.db,
        &caller.0,
        &payload.service_id,
        &payload.target_db,
        &credential_id,
        &generated.username,
    )
    .await?;

    let mut plaintext_password = generated.plaintext_password.clone();
    let response = ProvisionCredentialResponse {
        credential_id: credential_id.to_string(),
        service_id: payload.service_id.clone(),
        target_db: payload.target_db.clone(),
        username: generated.username.clone(),
        password: plaintext_password.clone(),
        created_at: created_at.to_rfc3339(),
    };

    plaintext_password.zeroize();
    Ok(Json(response))
}
