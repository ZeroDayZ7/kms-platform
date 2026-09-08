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

fn redis_acl_error(operation: &str, username: &str) -> AppError {
    tracing::error!(
        target: "infra::redis",
        operation,
        username,
        status = "failed",
        "Redis ACL operation failed"
    );
    AppError::Internal(format!("Redis {} operation failed", operation))
}

pub struct RedisTargetProvider {
    providers_acl: Arc<ProvidersAclSettings>,
}

impl RedisTargetProvider {
    pub fn new(providers_acl: Arc<ProvidersAclSettings>) -> Self {
        Self { providers_acl }
    }
}

impl RedisTargetProvider {
    /// Pomocnicza funkcja budująca klienta fred i nawiązująca połączenie z obsługą ACL username/password
    async fn connect_admin(&self, target_conn_str: &str) -> Result<Client, AppError> {
        let url = Url::parse(target_conn_str)
            .map_err(|_| AppError::Internal("Invalid Redis connection string format".into()))?;

        let host = url
            .host_str()
            .ok_or_else(|| AppError::Internal("Redis connection string missing host".into()))?;
        let port = url.port().unwrap_or(6379);

        // KLUCZOWA POPRAWKA: Odczyt username i password z URL dla Redis 6+ ACL
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
        role: &str,
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        tracing::info!(operation = "[R1] create_user", target = %target_conn_str, role = %role, "[R1] Redis create_user called");

        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Redis provider".to_string())
        })?;

        let encoded_password = BASE64.encode(password_bytes);
        let client = self.connect_admin(target_conn_str).await?;

        // Obtain policy for requesting service (role). Fail if missing — fail-fast semantics.
        let available_services: Vec<String> = self.providers_acl.services.keys().cloned().collect();
        tracing::debug!(operation = "[DBG] providers_acl_lookup", available_services = ?available_services, requested_role = %role, "Looking up Redis ACL policy for role");

        let policy = self.providers_acl.services.get(role).ok_or_else(|| {
            AppError::ConfigError(format!(
                "No Redis ACL policy configured for service '{}'. Available: {:?}",
                role,
                self.providers_acl
                    .services
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            ))
        })?;

        tracing::debug!(operation = "[DBG] providers_acl_policy", role = %role, policy = ?policy);

        let mut rules = policy.constraints.redis_acl_rules.clone().ok_or_else(|| {
            AppError::ConfigError(format!("No redis_acl_rules for service '{}'", role))
        })?;

        // Ensure password rule is present (format: >base64password)
        if !rules.iter().any(|r| r.starts_with('>')) {
            if rules.len() >= 1 {
                rules.insert(1, format!(">{}", encoded_password));
            } else {
                rules.push(format!(">{}", encoded_password));
            }
        }

        // Ensure admin restriction is present
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
            Err(e) => {
                tracing::error!(operation = "[R8] setuser_err", error = ?e, username = %role, "[R8] Redis ACL SETUSER failed");
                Err(redis_acl_error("create_user", role))
            }
        }
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        tracing::info!(operation = "[R9] revoke_user", target = %target_conn_str, username = %username, "[R9] revoke_user called");

        let client = self.connect_admin(target_conn_str).await?;

        tracing::info!(operation = "[R11] deluser", username = %username, "[R11] Executing ACL DELUSER via RESP ACL command");

        // Execute ACL DELUSER <username>
        match client.acl_deluser::<i64, _>(username).await {
            Ok(_) => {
                tracing::info!(operation = "[R11] deluser_ok", username = %username, target = "redis", "[R11] Redis ACL user removed");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(operation = "[R12] deluser_failed", error = ?e, username = %username, "[R12] ACL DELUSER failed, falling back to SETUSER off");

                client.acl_setuser(username, vec!["off".to_string()]).await
                    .map_err(|err| {
                        tracing::error!(operation = "[R13] disable_failed", error = ?err, username = %username, "[R13] Fallback disable failed");
                        redis_acl_error("drop_user", username)
                    })?;

                Ok(())
            }
        }
    }
}
