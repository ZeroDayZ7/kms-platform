use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info};

use crate::{domain::keys::models::ServiceId, errors::AppError, server::state::AppState};

type HmacSha256 = Hmac<Sha256>;

const MAX_CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_NONCE_TTL_SECONDS: u64 = 300;

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, AppError> {
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
            .get("X-Service-Name")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Service-Name");
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
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Nonce");
                AppError::Unauthorized
            })?;

        let body_hash = parts
            .headers
            .get("X-Body-SHA256")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-Body-SHA256");
                AppError::Unauthorized
            })?;

        let signature_hex = parts
            .headers
            .get("X-HMAC-Signature")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("❌ Brak nagłówka X-HMAC-Signature");
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
        let payload_to_sign = format!("{method}:{path}:{timestamp}:{nonce}:{body_hash}");

        let mut mac = HmacSha256::new_from_slice(service_cfg.secret.as_bytes())
            .map_err(|_| AppError::Internal("Błąd inicjalizacji HMAC".into()))?;
        mac.update(payload_to_sign.as_bytes());

        let expected_signature = hex::encode(mac.finalize().into_bytes());

        if let Some(redis) = state.redis_manager.as_ref() {
            let nonce_key = format!("hmac:nonce:{}:{}:{}", service_name, nonce, timestamp);
            let already_used = redis
                .set_if_not_exists(&nonce_key, "1", MAX_NONCE_TTL_SECONDS)
                .await
                .unwrap_or(false);
            if !already_used {
                error!(
                    "❌ HMAC nonce replay detected for service '{}'",
                    service_name
                );
                return Err(AppError::Unauthorized);
            }
        }

        debug!(service = %service_name, nonce = %nonce, timestamp = %timestamp, "validated HMAC metadata");

        if signature_hex
            .as_bytes()
            .ct_eq(expected_signature.as_bytes())
            .unwrap_u8()
            != 1
        {
            error!(
                "❌ Podpisy HMAC NIE są zgodne! Otrzymano: {}, Oczekiwano: {}",
                signature_hex, expected_signature
            );
            return Err(AppError::Unauthorized);
        }

        info!(
            "✅ [KMS-AUTH] Autoryzacja HMAC dla serwisu '{}' powiodła się",
            service_name
        );

        Ok(AuthenticatedService(ServiceId(service_name.to_string())))
    }
}
