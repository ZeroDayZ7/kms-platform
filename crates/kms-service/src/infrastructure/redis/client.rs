use crate::config::RedisConfig;
use crate::errors::{AppError, AppResult};
use fred::prelude::*;
use std::time::Duration;

pub struct RedisManager {
    client: Client,
}

impl RedisManager {
    pub async fn new(config: &RedisConfig) -> AppResult<Self> {
        let db_index: u8 = config.db.try_into().map_err(|_| {
            AppError::ValidationError(
                "Index bazy danych Redis musi mieścić się w zakresie 0-255".into(),
            )
        })?;

        let reconnect_policy = ReconnectPolicy::new_exponential(0, 100, 5000, 2);

        let redis_config = Config {
            server: ServerConfig::Centralized {
                server: Server::new(&config.host, config.port),
            },
            password: config.password.clone(),
            database: Some(db_index),
            ..Default::default()
        };

        let perf_config = PerformanceConfig::default();

        let client = Client::new(
            redis_config,
            Some(perf_config),
            None,
            Some(reconnect_policy),
        );

        client.connect();

        match tokio::time::timeout(Duration::from_secs(5), client.wait_for_connect()).await {
            Ok(Ok(_)) => {
                tracing::info!(
                    host = %config.host,
                    port = %config.port,
                    "🚀 Connected to Redis"
                );
                Ok(Self { client })
            }
            Ok(Err(e)) => Err(AppError::from(e)),
            Err(_) => Err(AppError::ConfigError(
                "Timeout podczas inicjalizacji połączenia z Redis".into(),
            )),
        }
    }

    pub async fn set_ex(&self, key: &str, value: &str, ttl_sec: u64) -> AppResult<()> {
        let expiration = Expiration::EX(
            ttl_sec
                .try_into()
                .map_err(|_| AppError::ValidationError("TTL jest zbyt duży".into()))?,
        );

        self.client
            .set::<(), _, _>(key, value, Some(expiration), None, false)
            .await?;

        Ok(())
    }

    pub async fn get(&self, key: &str) -> AppResult<Option<String>> {
        Ok(self.client.get::<Option<String>, _>(key).await?)
    }

    pub async fn del(&self, key: &str) -> AppResult<()> {
        Ok(self.client.del::<(), _>(key).await?)
    }

    pub async fn ping(&self) -> AppResult<()> {
        Ok(self.client.ping::<()>(None).await?)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}
