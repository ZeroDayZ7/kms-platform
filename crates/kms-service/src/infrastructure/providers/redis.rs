use crate::config::ProvidersAclSettings;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use super::{GeneratedCredential, TargetResourceProvider};
use crate::errors::AppError;
use zeroize::Zeroizing;

fn redis_acl_error(operation: &str, username: &str, err: impl std::fmt::Display) -> AppError {
    tracing::error!(
        target: "infra::redis",
        operation,
        username,
        status = "failed",
        error = %err,
        "Redis ACL operation failed"
    );
    AppError::Internal(format!(
        "Redis {} operation failed for user '{}': {}",
        operation, username, err
    ))
}

pub struct RedisTargetProvider {
    providers_acl: Arc<ProvidersAclSettings>,
}

impl RedisTargetProvider {
    pub fn new(providers_acl: Arc<ProvidersAclSettings>) -> Self {
        Self { providers_acl }
    }

    async fn connect_admin(&self, target_conn_str: &str) -> Result<Client, AppError> {
        let url = Url::parse(target_conn_str)
            .map_err(|_| AppError::Internal("Invalid Redis connection string format".into()))?;

        let host = url
            .host_str()
            .ok_or_else(|| AppError::Internal("Redis connection string missing host".into()))?;
        let port = url.port().unwrap_or(6379);

        let username = if url.username().is_empty() {
            None
        } else {
            Some(url.username().to_string())
        };
        let password = url.password().map(|s| s.to_string());
        let db_index: u8 = url.path().trim_start_matches('/').parse().unwrap_or(0);

        tracing::debug!(
            operation = "[R2] parsed_conn",
            host = %host,
            port = port,
            username = ?username,
            db_index = db_index,
            "[R2] Parsed connection parameters"
        );

        let reconnect_policy = ReconnectPolicy::new_exponential(0, 100, 5000, 2);

        let redis_config = Config {
            server: ServerConfig::Centralized {
                server: Server::new(host, port),
            },
            username,
            password,
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
                    operation = "[R3] connected",
                    "[R3] Connected to Redis admin endpoint"
                );
                Ok(client)
            }
            Ok(Err(e)) => {
                tracing::error!(operation = "[R3] connect_failed", error = %e, "[R3] Redis connection failed");
                Err(AppError::from(e))
            }
            Err(_) => {
                tracing::error!(
                    operation = "[R3] connect_timeout",
                    "[R3] Timeout during Redis connection initialization"
                );
                Err(AppError::ConfigError(
                    "Timeout during Redis connection initialization".into(),
                ))
            }
        }
    }
}

#[async_trait]
impl TargetResourceProvider for RedisTargetProvider {
    async fn create_user(
        &self,
        target_conn_str: &str,
        role: &str, // Wygenerowany, unikalny username (np. kms_authservic_a1b2c3d4)
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        tracing::info!(operation = "[R1] create_user", target = %target_conn_str, role = %role, "[R1] Redis create_user called");

        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Redis provider".to_string())
        })?;

        let encoded_password = BASE64.encode(password_bytes);
        let client = self.connect_admin(target_conn_str).await?;

        // POPRAWKA LOOKUPU ACL:
        // Szukamy dopasowania w konfiguracji JSON po pełnych i skróconych nazwach
        let policy = self.providers_acl.services.get(role)
            .or_else(|| {
                // Jeśli role to np. kms_authservic_a1b2c3d4, szukamy usera po prefiksie w konfiguracji
                self.providers_acl.services.keys().find(|k| {
                    let sanitized_k = k.replace('-', "");
                    role.contains(&sanitized_k) || role.contains(k.as_str())
                }).and_then(|k| self.providers_acl.services.get(k))
            })
            .ok_or_else(|| {
                AppError::ConfigError(format!(
                    "No Redis ACL policy configured for requested role/service '{}'. Available: {:?}",
                    role,
                    self.providers_acl.services.keys().cloned().collect::<Vec<_>>()
                ))
            })?;

        let redis_policy = policy.redis.as_ref().ok_or_else(|| {
            AppError::ConfigError(format!(
                "No redis configuration for service role '{}'",
                role
            ))
        })?;

        let mut rules = redis_policy.acl_rules.clone();
        if rules.is_empty() {
            return Err(AppError::ConfigError(format!(
                "No redis.acl_rules for service role '{}'",
                role
            )));
        }

        // Dodanie reguły hasła (>password)
        if !rules.iter().any(|r| r.starts_with('>')) {
            if !rules.is_empty() {
                rules.insert(1, format!(">{}", encoded_password));
            } else {
                rules.push(format!(">{}", encoded_password));
            }
        }

        // Restrykcja admina
        if !rules.iter().any(|r| r == "-@admin") {
            rules.push("-@admin".to_string());
        }

        tracing::info!(operation = "[R6] exec_acl_setuser", username = %role, "[R6] Executing ACL SETUSER via RESP ACL command");

        match client.acl_setuser(role, rules).await {
            Ok(_) => {
                tracing::info!(operation = "[R7] setuser_ok", username = %role, target = "redis", ttl_seconds = ttl_seconds, "[R7] Redis ACL SETUSER executed successfully");
                Ok(GeneratedCredential {
                    username: role.to_string(),
                    secret: Zeroizing::new(encoded_password),
                    ttl_seconds,
                })
            }
            Err(e) => Err(redis_acl_error("create_user", role, e)),
        }
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        tracing::info!(operation = "[R9] revoke_user", target = %target_conn_str, username = %username, "[R9] revoke_user called");

        let client = self.connect_admin(target_conn_str).await?;

        tracing::info!(operation = "[R11] deluser", username = %username, "[R11] Executing ACL DELUSER via RESP ACL command");

        match client.acl_deluser::<i64, _>(username).await {
            Ok(_) => {
                tracing::info!(operation = "[R11] deluser_ok", username = %username, target = "redis", "[R11] Redis ACL user removed");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(operation = "[R12] deluser_failed", error = ?e, username = %username, "[R12] ACL DELUSER failed, falling back to SETUSER off");

                client
                    .acl_setuser(username, vec!["off".to_string()])
                    .await
                    .map_err(|err| redis_acl_error("drop_user", username, err))?;

                Ok(())
            }
        }
    }
}
