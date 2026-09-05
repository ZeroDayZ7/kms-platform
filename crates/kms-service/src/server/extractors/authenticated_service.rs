use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info};

use crate::{domain::keys::models::ServiceId, errors::AppError, server::state::AppState};

type HmacSha256 = Hmac<Sha256>;

const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const MAX_NONCE_TTL_SECONDS: u64 = 300;

//#region parse_timestamp
fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, AppError> {
    if let Ok(epoch_seconds) = value.parse::<i64>() {
        return Utc
            .timestamp_opt(epoch_seconds, 0)
            .single()
            .ok_or(AppError::Unauthorized);
    }

    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AppError::Unauthorized)
}

pub struct AuthenticatedService(pub ServiceId);

impl FromRequestParts<AppState> for AuthenticatedService {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let service_name = parts
            .headers
            .get("X-Service-ID")
            .or_else(|| parts.headers.get("X-Service-Name"))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Service-ID / X-Service-Name");
                AppError::Unauthorized
            })?;

        let timestamp = parts
            .headers
            .get("X-Timestamp")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Timestamp");
                AppError::Unauthorized
            })?;
        let timestamp_dt = parse_timestamp(timestamp)?;
        let now = Utc::now();
        let skew = (now - timestamp_dt).num_seconds().abs();
        if skew > MAX_CLOCK_SKEW_SECONDS {
            error!("❌ Timestamp poza dozwolonym przesunięciem: skew={}s", skew);
            return Err(AppError::Unauthorized);
        }

        let nonce = parts
            .headers
            .get("X-Nonce")
            .or_else(|| parts.headers.get("x-nonce"))
            .and_then(|v| v.to_str().ok());

        let body_hash = parts
            .headers
            .get("X-Body-SHA256")
            .or_else(|| parts.headers.get("x-body-sha256"))
            .and_then(|v| v.to_str().ok());

        let signature_hex = parts
            .headers
            .get("X-Signature")
            .or_else(|| parts.headers.get("x-signature"))
            .or_else(|| parts.headers.get("X-HMAC-Signature"))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Signature / X-HMAC-Signature");
                AppError::Unauthorized
            })?;

        let service_cfg = state
            .settings
            .acl
            .services
            .get(service_name)
            .ok_or_else(|| {
                error!(
                    "❌ Serwis '{}' nie odnaleziony w konfiguracji ACL (services_acl.toml)",
                    service_name
                );
                AppError::Unauthorized
            })?;

        let method = parts.method.as_str();
        let path = parts.uri.path();
        let nonce_value = nonce.ok_or_else(|| {
            error!("❌ Brak nagłówka X-Nonce");
            AppError::Unauthorized
        })?;

        let mut payload = format!("{method}:{path}:{timestamp}:{nonce_value}");
        if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
            let body_hash_value = body_hash.ok_or_else(|| {
                error!("❌ Brak nagłówka X-Body-SHA256 dla żądania z body");
                AppError::Unauthorized
            })?;
            payload = format!("{method}:{path}:{timestamp}:{nonce_value}:{body_hash_value}");
        }

        let mut mac = HmacSha256::new_from_slice(service_cfg.secret.as_bytes())
            .map_err(|_| AppError::Internal("Błąd inicjalizacji HMAC".into()))?;
        mac.update(payload.as_bytes());
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        if signature_hex
            .as_bytes()
            .ct_eq(expected_signature.as_bytes())
            .unwrap_u8()
            != 1
        {
            error!(
                "❌ Podpisy HMAC NIE są zgodne! Otrzymano: {}, oczekiwano: {}",
                signature_hex, expected_signature
            );
            return Err(AppError::Unauthorized);
        }

        let nonce_key = format!("hmac:nonce:{}:{}:{}", service_name, nonce_value, timestamp);
        let already_used = state
            .nonce_store
            .mark_used(&nonce_key, MAX_NONCE_TTL_SECONDS)
            .await
            .unwrap_or(false);
        if !already_used {
            error!(
                "❌ HMAC nonce replay detected for service '{}'",
                service_name
            );
            return Err(AppError::Unauthorized);
        }

        debug!(
            service = %service_name,
            nonce = %nonce_value,
            timestamp = %timestamp,
            "validated HMAC metadata"
        );

        info!(
            "✅ [KMS-AUTH] Autoryzacja HMAC dla serwisu '{}' powiodła się",
            service_name
        );

        Ok(AuthenticatedService(ServiceId(service_name.to_string())))
    }
}
