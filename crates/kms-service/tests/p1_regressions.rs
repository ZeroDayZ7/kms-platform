use axum::{body::to_bytes, response::IntoResponse};
use kms_service::{domain::crypto::SecretBytes, errors::AppError, server::state::KeyCache};

#[test]
//#region secret_bytes_is_redacted_and_non_owning
fn secret_bytes_is_redacted_and_non_owning() {
    let secret = SecretBytes::new(vec![1, 2, 3, 4]);

    assert_eq!(secret.as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(format!("{}", secret), "[REDACTED]");
    assert_eq!(format!("{:?}", secret), "SecretBytes(\"[REDACTED]\")");
}

#[test]
//#region key_cache_uses_borrowed_view_and_invalidates_on_remove
fn key_cache_uses_borrowed_view_and_invalidates_on_remove() {
    let cache = KeyCache::new();
    cache.insert(
        &"svc".into(),
        kms_service::domain::keys::models::KeyAlgorithm::Ed25519,
        7,
        vec![9, 8, 7],
    );

    let value = cache
        .with_key(
            &"svc".into(),
            kms_service::domain::keys::models::KeyAlgorithm::Ed25519,
            |version, bytes| {
                assert_eq!(version, 7);
                assert_eq!(bytes, &[9, 8, 7]);
                bytes.to_vec()
            },
        )
        .expect("key should be available");

    assert_eq!(value, vec![9, 8, 7]);

    cache.remove(
        &"svc".into(),
        kms_service::domain::keys::models::KeyAlgorithm::Ed25519,
    );
    assert!(
        cache
            .with_key(
                &"svc".into(),
                kms_service::domain::keys::models::KeyAlgorithm::Ed25519,
                |_version, _bytes| "still-there",
            )
            .is_none()
    );
}

#[tokio::test]
async fn app_error_response_is_sanitized() {
    let response = AppError::Internal("debug path /tmp/secret".to_string()).into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let text = std::str::from_utf8(&bytes).expect("utf8 response body");

    assert!(text.contains("\"code\":\"INTERNAL_SERVER_ERROR\""));
    assert!(text.contains("\"message\":\"Internal server error\""));
    assert!(!text.contains("/tmp/secret"));
}
