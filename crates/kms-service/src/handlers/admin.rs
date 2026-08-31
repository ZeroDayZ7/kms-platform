use axum::{Json, extract::State};
use serde::Deserialize;
use chrono::Utc;
use x509_parser::parse_x509_certificate;
use pem::parse as pem_parse;
use sha2::{Sha256, Digest};
use uuid::Uuid;

use crate::{
    application::use_cases::import_bootstrap::{ImportBootstrapInput, import_bootstrap},
    application::use_cases::rewrap_keys::{RewrapKeysInput, rewrap_keys},
    errors::AppResult,
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

#[derive(Debug, Deserialize)]
pub struct RegisterIdentityRequest {
    pub cert_pem: String,
    #[serde(default = "default_super_admin_role")]
    pub role: String,
}

fn default_super_admin_role() -> String { "SUPER_ADMIN".to_string() }

#[derive(Debug, Deserialize)]
pub struct RewrapKeysRequest {
    pub target_version: i32,
    pub batch_size: usize,
}

pub async fn rewrap_keys_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Json(payload): Json<RewrapKeysRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let count = rewrap_keys(
        state.key_repo.clone(),
        state.crypto_service.clone(),
        RewrapKeysInput {
            target_master_version: payload.target_version,
            batch_size: payload.batch_size,
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "rewrapped": count,
        "target_version": payload.target_version,
        "batch_size": payload.batch_size,
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct ImportBootstrapRequest {
    pub version: u32,
    #[serde(default)]
    pub target_resources: Vec<serde_json::Value>,
    #[serde(default)]
    pub credentials: Vec<serde_json::Value>,
}

pub async fn import_bootstrap_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<ImportBootstrapRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let input = ImportBootstrapInput {
        version: payload.version,
        target_resources: payload.target_resources,
        credentials: payload.credentials,
    };

    let count = import_bootstrap(state.clone(), caller.0, input).await?;

    Ok(Json(serde_json::json!({"imported": count})))
}

pub async fn register_identity_handler(
    State(state): State<AppState>,
    AuthenticatedService(_caller): AuthenticatedService,
    Json(payload): Json<RegisterIdentityRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // parse PEM
    let pem = pem_parse(&payload.cert_pem.as_bytes()).map_err(|e| crate::errors::AppError::ValidationError(format!("Invalid PEM: {}", e)))?;
    let der = pem.contents();

    let (_, cert) = parse_x509_certificate(&der).map_err(|e| crate::errors::AppError::ValidationError(format!("Failed to parse cert: {}", e)))?;

    // extract CN by rendering subject to string and extracting CN=... token
    let subj_str = cert.tbs_certificate.subject.to_string();
    let mut subject_cn = String::new();
    if let Some(pos) = subj_str.find("CN=") {
        let rest = &subj_str[pos + 3..];
        let end = rest.find(',').unwrap_or(rest.len());
        subject_cn = rest[..end].to_string();
    }

    if subject_cn.is_empty() {
        return Err(crate::errors::AppError::ValidationError("Certificate subject CN not found".into()));
    }

    // serial number
    let serial = cert.tbs_certificate.raw_serial_as_string();

    // expires_at: convert to chrono::DateTime<Utc>
    let not_after_offset = cert.tbs_certificate.validity.not_after.to_datetime();
    let ts = not_after_offset.unix_timestamp();
    let not_after_chrono = chrono::DateTime::<chrono::Utc>::from_utc(chrono::NaiveDateTime::from_timestamp(ts, 0), chrono::Utc);

    // fingerprint SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&der);
    let fingerprint = hex::encode(hasher.finalize());

    // Insert into DB
    let now = Utc::now();
    let id = Uuid::new_v4();

    sqlx::query(r#"
        INSERT INTO client_identities (id, subject_cn, serial_number, fingerprint_sha256, identity_type, role, status, public_cert_pem, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $8, $9)
    "#)
    .bind(id)
    .bind(&subject_cn)
    .bind(&serial)
    .bind(&fingerprint)
    .bind("ADMIN")
    .bind(&payload.role)
    .bind(&payload.cert_pem)
    .bind(now)
    .bind(not_after_chrono)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({"inserted": true, "id": id})))
}
