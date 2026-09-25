use std::env;
use tokio::process::Command;

// This is a lightweight integration test to exercise idempotency of ca_init handling.
// It requires a running Postgres instance pointed by DATABASE_URL and a reachable vHSM socket.
// For CI, consider mocking the HSM client.

#[tokio::test]
async fn ca_init_idempotency_smoke() {
    // This test is intended to run locally by the developer; it will skip if DATABASE_URL not set.
    let db = match env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DATABASE_URL not set; skipping integration test");
            return;
        }
    };

    // We'll invoke the CLI twice with same tag; the second run should be no-op.
    let socket = env::var("VHSM_SOCKET_PATH").unwrap_or_else(|_| "".to_string());
    let tag = format!("test-ca-{}", uuid::Uuid::new_v4());

    // First run
    let status1 = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "kms-ceremony-cli",
            "--",
            "ca",
            "init",
            &socket,
            &tag,
        ])
        .status()
        .await
        .expect("failed to run first ca init");
    assert!(status1.success());

    // Second run (should be idempotent)
    let status2 = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "kms-ceremony-cli",
            "--",
            "ca",
            "init",
            &socket,
            &tag,
        ])
        .status()
        .await
        .expect("failed to run second ca init");
    assert!(status2.success());
}
