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
            tracing::info_span!(
                "http-request",
                method = %request.method(),
                uri = %request.uri().path(),
            )
        })
        .on_request(|request: &Request<Body>, _span: &Span| {
            tracing::info!("started {} {}", request.method(), request.uri().path());
        })
        .on_response(|response: &Response, latency: Duration, _span: &Span| {
            tracing::info!(
                status = %response.status().as_u16(),
                latency = ?latency,
                "finished processing"
            );
        })
}
