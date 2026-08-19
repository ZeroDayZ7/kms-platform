use axum::http::{HeaderName, HeaderValue};
use tower::ServiceBuilder;
use tower::layer::util::{Identity, Stack};
use tower_http::set_header::SetResponseHeaderLayer;

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
