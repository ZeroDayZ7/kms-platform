use axum::{
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower::ServiceBuilder;
use tower::layer::util::{Identity, Stack};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::server::state::AppState;

const MAX_HMAC_BODY_SIZE: usize = 10 * 1024 * 1024;

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

pub async fn hmac_security_middleware(
    State(_state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, MAX_HMAC_BODY_SIZE).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => return crate::errors::AppError::Unauthorized.into_response(),
    };

    if matches!(parts.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        let header = match parts
            .headers
            .get("X-Body-SHA256")
            .or_else(|| parts.headers.get("x-body-sha256"))
            .and_then(|value| value.to_str().ok())
        {
            Some(value) => value,
            None => return crate::errors::AppError::Unauthorized.into_response(),
        };

        let actual = hex::encode(Sha256::digest(&body_bytes));
        if header.as_bytes().ct_eq(actual.as_bytes()).unwrap_u8() != 1 {
            return crate::errors::AppError::Unauthorized.into_response();
        }
    }

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
