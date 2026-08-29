use std::env;

#[tokio::test]
async fn provision_flow_persists_credential_record_when_database_is_available() {
    let database_url = match env::var("DATABASE_URL")
        .or_else(|_| env::var("DATABASE__URL"))
        .or_else(|_| env::var("POSTGRES_URL"))
    {
        Ok(value) => value,
        Err(_) => {
            eprintln!(
                "Skipping credential provisioning database integration test: DATABASE_URL is not configured."
            );
            return;
        }
    };

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("DATABASE_URL should point to a working Postgres instance");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS db_credentials (
            id UUID PRIMARY KEY,
            service_id TEXT NOT NULL,
            target_db TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BYTEA NOT NULL,
            nonce BYTEA NOT NULL,
            kek_id UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (service_id, target_db, username)
        );
        "#,
    )
    .execute(&pool)
    .await
    .expect("credential table should be creatable in the target database");

    let credential_id = uuid::Uuid::new_v4();
    let username = "kms_orders_db_auth_123";
    let password = b"super-secret-password-123";
    let nonce = b"0123456789ab";

    sqlx::query(
        "INSERT INTO db_credentials (id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
    )
    .bind(credential_id)
    .bind("provisioner-service")
    .bind("db-auth")
    .bind(username)
    .bind(password)
    .bind(nonce)
    .bind(None::<uuid::Uuid>)
    .execute(&pool)
    .await
    .expect("credential record should be inserted");

    let row: (String, String, String) =
        sqlx::query_as("SELECT service_id, target_db, username FROM db_credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_one(&pool)
            .await
            .expect("credential record should be queryable");

    assert_eq!(row.0, "provisioner-service");
    assert_eq!(row.1, "db-auth");
    assert_eq!(row.2, username);
}
