use crate::config::acl::ControlAction;
use crate::errors::{AppError, AppResult};
use crate::server::{extractors::authenticated_service::AuthenticatedService, state::AppState};
use axum::{Json, extract::State};
use base64::Engine;
use chrono::{DateTime, Utc};
use kms_db::repositories::AuditQueries;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub limit: Option<usize>,
    pub full: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub total_checked: usize,
    pub ok_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuditLogRow {
    pub id: Uuid,
    pub caller_service: String,
    pub target_service: String,
    pub action: String,
    pub algorithm: String,
    pub status: String,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<Vec<u8>>,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(clippy::collapsible_if, clippy::redundant_closure)]
pub async fn verify_audit_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    axum::extract::Query(q): axum::extract::Query<VerifyQuery>,
) -> AppResult<Json<VerifyReport>> {
    if !state
        .settings
        .acl
        .has_control_action(&caller, &ControlAction::AuditVerify)
    {
        return Err(AppError::Forbidden);
    }

    let limit = q.limit.unwrap_or(1000);
    let full = q.full.unwrap_or(false);

    // Fetch rows using native sqlx queries
    let rows: Vec<AuditLogRow> = AuditQueries::list_recent(&state.db, Some(limit), full)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?
        .into_iter()
        .map(|row| AuditLogRow {
            id: row.id,
            caller_service: row.caller_service,
            target_service: row.target_service,
            action: row.action,
            algorithm: row.algorithm,
            status: row.status,
            reason: row.reason,
            prev_hash: row.prev_hash,
            hash: row.hash,
            signature: row.signature,
            request_id: row.request_id,
            operation_id: row.operation_id,
            target_id: row.target_id,
            metadata: row.metadata,
            created_at: row.created_at,
        })
        .collect();

    if rows.is_empty() {
        return Ok(Json(VerifyReport {
            ok: true,
            total_checked: 0,
            ok_count: 0,
            errors: vec![],
        }));
    }

    let mut errors: Vec<String> = Vec::new();
    let mut anchor_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let records_to_verify = if !full && rows.len() > limit {
        anchor_hash = rows[0].hash.clone();
        rows.into_iter().skip(1).collect::<Vec<_>>()
    } else {
        rows
    };

    let mut last_hash = anchor_hash;
    let mut ok_count = 0usize;

    let signing_keys: Vec<String> = AuditQueries::active_signing_public_keys(&state.db)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    let mut pubkeys: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
    for pem in signing_keys.iter() {
        if let Ok(pk) = parse_ed25519_pub_from_pem(pem) {
            pubkeys.push(pk);
        }
    }

    for rec in records_to_verify.iter() {
        if rec.prev_hash != last_hash {
            errors.push(format!(
                "Integrity violation at id {}: prev_hash mismatch (expected {} got {})",
                rec.id, last_hash, rec.prev_hash
            ));
            break;
        }

        let computed = kms_core::audit::compute_audit_hash(&kms_core::audit::AuditHashInput {
            id: &rec.id.to_string(),
            caller_service: &rec.caller_service,
            target_service: &rec.target_service,
            action: &rec.action,
            algorithm: &rec.algorithm,
            status: &rec.status,
            reason: rec.reason.as_deref(),
            prev_hash: &rec.prev_hash,
            timestamp: &rec.created_at,
            request_id: rec.request_id.as_deref(),
            operation_id: rec.operation_id.as_deref(),
            target_id: rec.target_id.as_deref(),
            metadata: rec.metadata.as_deref(),
        });

        if computed != rec.hash {
            errors.push(format!(
                "Integrity violation at id {}: hash mismatch (expected {} got {})",
                rec.id, rec.hash, computed
            ));
            break;
        }

        if let Some(sig_bytes) = &rec.signature {
            if sig_bytes.len() == 64 && !pubkeys.is_empty() {
                let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        errors.push(format!("Invalid signature length at id {}", rec.id));
                        break;
                    }
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

                let mut verified = false;
                for pk in pubkeys.iter() {
                    if pk.verify_strict(computed.as_bytes(), &sig).is_ok() {
                        verified = true;
                        break;
                    }
                }

                if !verified {
                    errors.push(format!("Signature verification failed for id {}", rec.id));
                    break;
                }
            }
        }

        last_hash = rec.hash.clone();
        ok_count += 1;
    }

    let ok = errors.is_empty();
    Ok(Json(VerifyReport {
        ok,
        total_checked: ok_count + errors.len(),
        ok_count,
        errors,
    }))
}

fn parse_ed25519_pub_from_pem(pem: &str) -> Result<ed25519_dalek::VerifyingKey, ()> {
    let b64 = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|_| ())?;
    if der.len() >= 32 {
        let pk_bytes = &der[der.len() - 32..];
        let pk_arr: [u8; 32] = match pk_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Err(()),
        };
        match ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => Ok(k),
            Err(_) => Err(()),
        }
    } else {
        Err(())
    }
}

pub async fn audit_logs_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
) -> AppResult<Json<serde_json::Value>> {
    if !state
        .settings
        .acl
        .has_control_action(&caller, &ControlAction::AuditRead)
    {
        return Err(AppError::Forbidden);
    }

    let rows: Vec<AuditLogRow> = AuditQueries::list_recent(&state.db, None, true)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?
        .into_iter()
        .map(|row| AuditLogRow {
            id: row.id,
            caller_service: row.caller_service,
            target_service: row.target_service,
            action: row.action,
            algorithm: row.algorithm,
            status: row.status,
            reason: row.reason,
            prev_hash: row.prev_hash,
            hash: row.hash,
            signature: row.signature,
            request_id: row.request_id,
            operation_id: row.operation_id,
            target_id: row.target_id,
            metadata: row.metadata,
            created_at: row.created_at,
        })
        .collect();

    let signing_keys: Vec<String> = AuditQueries::active_signing_public_keys(&state.db)
        .await
        .map_err(|err| {
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

    let logs: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|rec| {
            let mut map = serde_json::Map::new();
            map.insert(
                "id".to_string(),
                serde_json::Value::String(rec.id.to_string()),
            );
            map.insert(
                "caller_service".to_string(),
                serde_json::Value::String(rec.caller_service),
            );
            map.insert(
                "target_service".to_string(),
                serde_json::Value::String(rec.target_service),
            );
            map.insert("action".to_string(), serde_json::Value::String(rec.action));
            map.insert(
                "algorithm".to_string(),
                serde_json::Value::String(rec.algorithm),
            );
            map.insert("status".to_string(), serde_json::Value::String(rec.status));
            map.insert(
                "reason".to_string(),
                match rec.reason {
                    Some(x) => serde_json::Value::String(x),
                    None => serde_json::Value::Null,
                },
            );
            map.insert(
                "prev_hash".to_string(),
                serde_json::Value::String(rec.prev_hash),
            );
            map.insert("hash".to_string(), serde_json::Value::String(rec.hash));
            map.insert(
                "created_at".to_string(),
                serde_json::Value::String(rec.created_at.to_rfc3339()),
            );
            serde_json::Value::Object(map)
        })
        .collect();

    Ok(Json(
        serde_json::json!({"logs": logs, "signing_public_keys": signing_keys}),
    ))
}
