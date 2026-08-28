use kms_ceremony_cli::cli::hmac::{canonical_request_string, sign_hmac_sha256};

#[test]
fn canonical_string_uses_method_path_timestamp_format() {
    assert_eq!(
        canonical_request_string("GET", "/api/v1/audit/verify", 1700000000),
        "GET:/api/v1/audit/verify:1700000000"
    );
}

#[test]
fn hmac_signature_is_lowercase_hex() {
    let sig = sign_hmac_sha256(
        "super-long-random-secret-for-kms-cli-hmac-64-bytes",
        "GET",
        "/api/v1/audit/verify",
        1700000000,
    );
    assert_eq!(sig, sig.to_ascii_lowercase());
    assert!(!sig.is_empty());
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
}
