use crate::server::state::AppState;
use axum::{body::Body, http::Request, response::IntoResponse, response::Response};
use axum::{extract::State, http::StatusCode, middleware::Next};
use serde::Serialize;

#[derive(Serialize)]
struct LockedResponse {
    error: &'static str,
    message: &'static str,
}

pub async fn kms_lock_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Permit health and status and unlock endpoints regardless of lock state
    if path == "/health" || path == "/status" || path == "/api/v1/admin/ceremony/unlock" {
        return next.run(req).await;
    }

    if state.is_unlocked() {
        return next.run(req).await;
    }

    let body = LockedResponse {
        error: "KMS_LOCKED",
        message: "KMS is locked. Key ceremony unlock required.",
    };

    (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response()
}
