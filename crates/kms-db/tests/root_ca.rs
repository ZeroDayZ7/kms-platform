use chrono::{Duration, Utc};
use kms_db::PgPool;
use kms_db::repositories::RootCaQueries;
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

#[tokio::test]
async fn root_ca_lifecycle() {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("SKIP: no DATABASE_URL configured for kms-db root_ca tests");
            return;
        }
    };

    let mut conn = PgConnection::connect(&database_url).await.unwrap();

    // Ensure no root cas exist for tag 'test-root'
    let exists_before = RootCaQueries::exists_by_tag(
        &kms_db::connect(&kms_db::DatabaseConfig::default())
            .await
            .unwrap(),
        "test-root",
    )
    .await
    .unwrap_or(false);
    assert!(!exists_before, "Root CA should not exist before test");

    // Insert a new root CA
    let id = Uuid::new_v4();
    let pool = kms_db::connect(&kms_db::DatabaseConfig::default())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();

    let now = Utc::now();
    let expires = Some(now + Duration::days(365));

    let inserted = RootCaQueries::insert_root_ca(
        &mut tx,
        id,
        "test-root",
        "RSA2048",
        b"encrypted_placeholder",
        Uuid::new_v4(),
        1,
        "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
        "SN123",
        "Active",
        now,
        expires,
    )
    .await
    .unwrap();

    assert!(inserted, "Insert should report success");
    tx.commit().await.unwrap();

    // Read back by tag
    let fetched = RootCaQueries::fetch_active_by_tag(&pool, "test-root")
        .await
        .unwrap();
    assert!(fetched.is_some(), "Should fetch inserted root ca");
    let row = fetched.unwrap();
    assert_eq!(row.ca_tag, "test-root");
    assert_eq!(row.serial_number, "SN123");

    // Idempotent exists_by_tag
    let exists_again = RootCaQueries::exists_by_tag(&pool, "test-root")
        .await
        .unwrap();
    assert!(exists_again, "exists_by_tag should be true after insert");

    // Unique tag - attempting to insert again with same id should be no-op
    let mut tx2 = pool.begin().await.unwrap();
    let inserted2 = RootCaQueries::insert_root_ca(
        &mut tx2,
        id,
        "test-root",
        "RSA2048",
        b"encrypted_placeholder2",
        Uuid::new_v4(),
        1,
        "-----BEGIN CERTIFICATE-----\nTEST2\n-----END CERTIFICATE-----",
        "SN1234",
        "Active",
        now,
        expires,
    )
    .await
    .unwrap();
    // insertion with same id should do nothing
    assert!(!inserted2, "Second insert with same id should not insert");
    tx2.commit().await.unwrap();

    // Update encrypted private key (simulate rewrap)
    let new_encrypted = b"rewrapped_placeholder";
    let mut tx3 = pool.begin().await.unwrap();
    RootCaQueries::update_encrypted_private_key(&mut tx3, id, new_encrypted, 2)
        .await
        .unwrap();
    tx3.commit().await.unwrap();

    let fetched_after = RootCaQueries::fetch_by_id(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_after.kek_version, 2);
}
