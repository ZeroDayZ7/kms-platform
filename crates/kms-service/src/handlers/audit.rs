use crate::config::acl::ControlAction;
use crate::errors::{AppError, AppResult};
use crate::server::{extractors::authenticated_service::AuthenticatedService, state::AppState};
use axum::{Json, extract::State};
use base64::Engine;
use serde::{Deserialize, Serialize};

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

    // Fetch rows depending on full vs partial
    let rows = if full {
        crate::infrastructure::sqlc::queries::get_audit_logs_all(&state.db)
            .await
            .map_err(|e| crate::errors::AppError::from(e))?
    } else {
        // fetch last (limit + 1) to possibly get anchor
        let mut fetched = crate::infrastructure::sqlc::queries::get_audit_logs_last_n(
            &state.db,
            (limit + 1) as i64,
        )
        .await
        .map_err(|e| crate::errors::AppError::from(e))?;
        // rows are in DESC order (newest first) -> reverse to chronological
        fetched.reverse();
        fetched
    };

    if rows.is_empty() {
        return Ok(Json(VerifyReport {
            ok: true,
            total_checked: 0,
            ok_count: 0,
            errors: vec![],
        }));
    }

    // If not full and we fetched limit+1, the first row may be anchor
    let mut errors: Vec<String> = Vec::new();
    let mut anchor_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let records_to_verify = if !full && rows.len() > limit {
        anchor_hash = rows[0].hash.clone();
        rows.into_iter().skip(1).collect::<Vec<_>>()
    } else {
        rows
    };

    use sha2::{Digest, Sha256};

    let mut last_hash = anchor_hash;
    let mut ok_count = 0usize;

    // Load active signing public keys (PEM) to allow signature verification if present
    let signing_keys =
        crate::infrastructure::sqlc::queries::get_active_signing_public_keys(&state.db)
            .await
            .map_err(crate::errors::AppError::from)?;

    let mut pubkeys: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
    for row in signing_keys.iter() {
        if let Ok(pk) = parse_ed25519_pub_from_pem(&row.public_key_pem) {
            pubkeys.push(pk);
        }
    }

    for rec in records_to_verify.iter() {
        // check prev_hash matches last_hash
        if rec.prev_hash != last_hash {
            errors.push(format!(
                "Integrity violation at id {}: prev_hash mismatch (expected {} got {})",
                rec.id, last_hash, rec.prev_hash
            ));
            break;
        }

        // canonicalize
        let mut map = serde_json::Map::new();
        map.insert(
            "id".to_string(),
            serde_json::Value::String(rec.id.to_string()),
        );
        map.insert(
            "caller_service".to_string(),
            serde_json::Value::String(rec.caller_service.clone()),
        );
        map.insert(
            "target_service".to_string(),
            serde_json::Value::String(rec.target_service.clone()),
        );
        map.insert(
            "action".to_string(),
            serde_json::Value::String(rec.action.clone()),
        );
        map.insert(
            "algorithm".to_string(),
            serde_json::Value::String(rec.algorithm.clone()),
        );
        map.insert(
            "status".to_string(),
            serde_json::Value::String(rec.status.clone()),
        );
        map.insert(
            "reason".to_string(),
            match &rec.reason {
                Some(x) => serde_json::Value::String(x.clone()),
                None => serde_json::Value::Null,
            },
        );
        map.insert(
            "prev_hash".to_string(),
            serde_json::Value::String(rec.prev_hash.clone()),
        );
        map.insert(
            "timestamp".to_string(),
            serde_json::Value::String(rec.created_at.to_rfc3339()),
        );

        let payload = serde_json::Value::Object(map).to_string();
        let computed = hex::encode(Sha256::digest(payload.as_bytes()));

        if computed != rec.hash {
            errors.push(format!(
                "Integrity violation at id {}: hash mismatch (expected {} got {})",
                rec.id, rec.hash, computed
            ));
            break;
        }

        // verify signature if present
        if let Some(sig_bytes) = &rec.signature {
            if sig_bytes.len() == 64 && !pubkeys.is_empty() {
                // convert signature Vec<u8> -> [u8;64]
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
    // extract base64 lines
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

    let rows = crate::infrastructure::sqlc::queries::get_audit_logs_all(&state.db)
        .await
        .map_err(crate::errors::AppError::from)?;

    // try to fetch active signing public key PEMs
    let signing_keys =
        crate::infrastructure::sqlc::queries::get_active_signing_public_keys(&state.db)
            .await
            .map_err(crate::errors::AppError::from)?;

    let keys: Vec<String> = signing_keys.into_iter().map(|r| r.public_key_pem).collect();

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
        serde_json::json!({"logs": logs, "signing_public_keys": keys}),
    ))
}
