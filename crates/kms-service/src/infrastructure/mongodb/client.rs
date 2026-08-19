// src/infrastructure/database.rs
use crate::config::DatabaseConfig;
use crate::errors::{AppError, AppResult};
use mongodb::bson::doc;
use mongodb::{
    Client, Database,
    options::{ClientOptions, ServerApi, ServerApiVersion},
};

pub async fn init_mongo(db_set: &DatabaseConfig) -> AppResult<Database> {
    let auth_source = db_set.auth_source.as_deref().unwrap_or("admin");

    let auth = match (db_set.user.as_deref(), db_set.password.as_deref()) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => format!("{u}:{p}@"),
        _ => String::new(),
    };

    let client_uri = format!(
        "mongodb://{}{}:{}/{}?authSource={}&directConnection=true",
        auth, db_set.host, db_set.port, db_set.name, auth_source
    );

    let mut client_options = ClientOptions::parse(&client_uri)
        .await
        .map_err(|e| AppError::ConfigError(format!("Błędny URI MongoDB: {}", e)))?;

    client_options.retry_writes = Some(true);
    client_options.retry_reads = Some(true);
    client_options.max_pool_size = Some(db_set.pool_size);
    client_options.server_api = Some(ServerApi::builder().version(ServerApiVersion::V1).build());

    let client = Client::with_options(client_options)?;

    client
        .database(&db_set.name)
        .run_command(doc! {"ping": 1})
        .await?;

    tracing::info!("✅ Connected to MongoDB");
    Ok(client.database(&db_set.name))
}
