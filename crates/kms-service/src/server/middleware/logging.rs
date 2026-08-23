// src/server/middleware/logging.rs
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::Span;

fn request_id_for_request(request: &Request<Body>) -> String {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

#[allow(clippy::type_complexity)]
pub fn http_trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl Fn(&Request<Body>) -> Span + Clone,
    impl Fn(&Request<Body>, &Span) + Clone,
    impl Fn(&Response, Duration, &Span) + Clone,
> {
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request<Body>| {
            let request_id = request_id_for_request(request);

            tracing::info_span!(
                "http-request",
                request_id = %request_id,
                method = %request.method(),
                path = %request.uri().path(),
            )
        })
        .on_request(|request: &Request<Body>, span: &Span| {
            tracing::info!(
                parent: span,
                method = %request.method(),
                path = %request.uri().path(),
                "started request"
            );
        })
        .on_response(|response: &Response, latency: Duration, span: &Span| {
            tracing::info!(
                parent: span,
                status = %response.status().as_u16(),
                latency_ms = %latency.as_millis(),
                "finished processing"
            );
        })
}

#[cfg(test)]
mod tests {
    use super::request_id_for_request;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn request_id_uses_header_when_present() {
        let request = Request::builder()
            .uri("/ping")
            .header("x-request-id", "req-123")
            .body(Body::empty())
            .unwrap();

        assert_eq!(request_id_for_request(&request), "req-123");
    }

    #[test]
    fn request_id_is_generated_when_header_missing() {
        let request = Request::builder().uri("/ping").body(Body::empty()).unwrap();

        let request_id = request_id_for_request(&request);
        assert!(!request_id.trim().is_empty());
        assert_eq!(request_id.len(), 36);
    }
}
