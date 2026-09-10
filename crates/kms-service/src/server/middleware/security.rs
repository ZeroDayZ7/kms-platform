use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderName, HeaderValue, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower::ServiceBuilder;
use tower::layer::util::{Identity, Stack};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{domain::keys::models::ServiceId, server::state::AppState};

type HmacSha256 = Hmac<Sha256>;

const MAX_HMAC_BODY_SIZE: usize = 10 * 1024 * 1024;
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const MAX_NONCE_TTL_SECONDS: u64 = 300;

type SecurityHeadersLayer = ServiceBuilder<
    Stack<
        SetResponseHeaderLayer<HeaderValue>,
        Stack<
            SetResponseHeaderLayer<HeaderValue>,
            Stack<
                SetResponseHeaderLayer<HeaderValue>,
                Stack<SetResponseHeaderLayer<HeaderValue>, Identity>,
            >,
        >,
    >,
>;

// Parse timestamp (either epoch seconds or RFC3339)
fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, crate::errors::AppError> {
    if let Ok(epoch_seconds) = value.parse::<i64>() {
        return Utc
            .timestamp_opt(epoch_seconds, 0)
            .single()
            .ok_or(crate::errors::AppError::Unauthorized);
    }

    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| crate::errors::AppError::Unauthorized)
}

pub async fn hmac_security_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();

    let body_bytes = match to_bytes(body, MAX_HMAC_BODY_SIZE).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => return crate::errors::AppError::Unauthorized.into_response(),
    };

    // If path is in public_endpoints, skip HMAC verification
    let path = parts.uri.path();
    if state
        .settings
        .auth
        .public_endpoints
        .iter()
        .any(|p| p == path)
    {
        tracing::debug!(path = %path, "Public endpoint - skipping HMAC verification");
        let request = Request::from_parts(parts, Body::from(body_bytes));
        return next.run(request).await;
    }

    // Read required headers
    let service_name = parts
        .headers
        .get("X-Service-ID")
        .or_else(|| parts.headers.get("X-Service-Name"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("Missing X-Service-ID / X-Service-Name header");
            crate::errors::AppError::Unauthorized
        });

    let service_name = match service_name {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };

    let timestamp = match parts
        .headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v,
        None => {
            tracing::error!("Missing X-Timestamp header");
            return crate::errors::AppError::Unauthorized.into_response();
        }
    };

    let timestamp_dt = match parse_timestamp(timestamp) {
        Ok(dt) => dt,
        Err(e) => return e.into_response(),
    };

    let now = Utc::now();
    let skew = (now - timestamp_dt).num_seconds().abs();
    if skew > MAX_CLOCK_SKEW_SECONDS {
        tracing::error!(skew, "Timestamp skew too large");
        return crate::errors::AppError::Unauthorized.into_response();
    }

    let nonce = parts
        .headers
        .get("X-Nonce")
        .or_else(|| parts.headers.get("x-nonce"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("Missing X-Nonce header");
            crate::errors::AppError::Unauthorized
        });

    let nonce = match nonce {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };

    let signature_hex = parts
        .headers
        .get("X-Signature")
        .or_else(|| parts.headers.get("x-signature"))
        .or_else(|| parts.headers.get("X-HMAC-Signature"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("Missing X-Signature / X-HMAC-Signature header");
            crate::errors::AppError::Unauthorized
        });

    let signature_hex = match signature_hex {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };

    // Compute body SHA256 for all methods (empty body allowed)
    let body_sha256 = hex::encode(Sha256::digest(&body_bytes));

    // Build canonical payload: METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256
    let method = parts.method.as_str();
    let path = parts.uri.path();
    let payload = format!(
        "{}:{}:{}:{}:{}",
        method, path, timestamp, nonce, body_sha256
    );

    // Lookup service secret in ACL
    let service_cfg = state
        .settings
        .acl
        .services
        .get(service_name)
        .ok_or_else(|| {
            tracing::error!(service = %service_name, "Service not found in ACL");
            crate::errors::AppError::Unauthorized
        });

    let service_cfg = match service_cfg {
        Ok(cfg) => cfg,
        Err(err) => return err.into_response(),
    };

    // Validate HMAC signature
    let mut mac = match HmacSha256::new_from_slice(service_cfg.secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return crate::errors::AppError::Internal("HMAC init failed".into()).into_response();
        }
    };
    mac.update(payload.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if signature_hex
        .as_bytes()
        .ct_eq(expected_signature.as_bytes())
        .unwrap_u8()
        != 1
    {
        tracing::error!(service = %service_name, "HMAC verification failed");
        return crate::errors::AppError::Unauthorized.into_response();
    }

    // Protect against replay via nonce store
    let nonce_key = format!("hmac:nonce:{}:{}:{}", service_name, nonce, timestamp);
    let already_used = state
        .nonce_store
        .mark_used(&nonce_key, MAX_NONCE_TTL_SECONDS)
        .await
        .unwrap_or(false);
    if !already_used {
        tracing::error!(service = %service_name, "HMAC nonce replay detected");
        return crate::errors::AppError::Unauthorized.into_response();
    }

    tracing::debug!(service = %service_name, "HMAC verification succeeded");

    // Insert verified ServiceId into request extensions for downstream extractors
    parts.extensions.insert(ServiceId(service_name.to_string()));

    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
}

//#region create_security_headers_layer
pub fn create_security_headers_layer() -> SecurityHeadersLayer {
    ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none';"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
}
