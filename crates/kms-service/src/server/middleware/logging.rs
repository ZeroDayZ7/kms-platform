// src/server/middleware/logging.rs
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::Span;

#[allow(clippy::type_complexity)]
pub fn http_trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl Fn(&Request<Body>) -> Span + Clone,
    impl Fn(&Request<Body>, &Span) + Clone,
    impl Fn(&Response, Duration, &Span) + Clone,
> {
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request<Body>| {
            let request_id = request
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

            tracing::info_span!(
                "http-request",
                request_id = %request_id,
                method = %request.method(),
                path = %request.uri().path(),
            )
        })
        .on_request(|request: &Request<Body>, _span: &Span| {
            let request_id = request
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown");
            tracing::info!(
                request_id = %request_id,
                method = %request.method(),
                path = %request.uri().path(),
                "started request"
            );
        })
        .on_response(|response: &Response, latency: Duration, _span: &Span| {
            let request_id = std::env::var("REQUEST_ID").unwrap_or_else(|_| "unknown".to_string());
            tracing::info!(
                request_id = %request_id,
                status = %response.status().as_u16(),
                latency_ms = %latency.as_millis(),
                "finished processing"
            );
        })
}
