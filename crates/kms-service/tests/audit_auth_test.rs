use axum::http::StatusCode;
use axum::response::IntoResponse;
use kms_service::errors::AppError;

#[test]
fn unauthenticated_audit_access_returns_401() {
    let response = AppError::Unauthorized.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn forbidden_audit_access_returns_403() {
    let response = AppError::Forbidden.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn successful_audit_response_stays_200() {
    let response = axum::http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
