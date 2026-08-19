use axum::{extract::FromRequestParts, http::request::Parts};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{error, info};

use crate::{domain::keys::models::ServiceId, errors::AppError, server::state::AppState};

type HmacSha256 = Hmac<Sha256>;

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
        let payload_to_sign = format!("{method}:{path}:{timestamp}");

        let mut mac = HmacSha256::new_from_slice(service_cfg.secret.as_bytes())
            .map_err(|_| AppError::Internal("Błąd inicjalizacji HMAC".into()))?;
        mac.update(payload_to_sign.as_bytes());

        let expected_signature = hex::encode(mac.finalize().into_bytes());

        info!("🔍 [KMS-AUTH] Service: {}", service_name);
        info!("🔍 [KMS-AUTH] String do podpisu: '{}'", payload_to_sign);
        info!("🔑 [KMS-AUTH] Otrzymany podpis: {}", signature_hex);
        info!("🔑 [KMS-AUTH] Oczekiwany podpis: {}", expected_signature);

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
