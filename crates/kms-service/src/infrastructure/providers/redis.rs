use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use fred::prelude::*;
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

pub struct RedisTargetProvider;

#[async_trait]
impl TargetResourceProvider for RedisTargetProvider {
    async fn create_user(
        &self,
        target_conn_str: &str,
        role: &str,
        ttl_seconds: i64,
        password: Option<&[u8]>,
    ) -> Result<GeneratedCredential, AppError> {
        let password_bytes = password.ok_or_else(|| {
            AppError::Internal("No password provided for Redis provider".to_string())
        })?;

        // Re-encode to base64 so the returned plaintext password matches
        // the `plaintext_password` value produced by the caller (which is base64).
        let encoded_password = BASE64.encode(password_bytes);

        // Parse connection string (expecting a redis:// URL)
        let url = Url::parse(target_conn_str).map_err(|_| {
            AppError::Internal("Invalid Redis connection string format".into())
        })?;

        let host = url.host_str().ok_or_else(|| {
            AppError::Internal("Redis connection string missing host".into())
        })?;
        let port = url.port().unwrap_or(6379);

        // optional password in the URL (admin password)
        let admin_password = url.password().map(|s| s.to_string());

        // optional DB index from path
        let db_index: u8 = url
            .path()
            .trim_start_matches('/')
            .parse()
            .unwrap_or(0);

        let reconnect_policy = ReconnectPolicy::new_exponential(0, 100, 5000, 2);

        let redis_config = Config {
            server: ServerConfig::Centralized {
                server: Server::new(host, port),
            },
            password: admin_password,
            database: Some(db_index),
            ..Default::default()
        };

        let perf_config = PerformanceConfig::default();

        let client = Client::new(redis_config, Some(perf_config), None, Some(reconnect_policy));

        client.connect();

        match tokio::time::timeout(Duration::from_secs(5), client.wait_for_connect()).await {
            Ok(Ok(_)) => tracing::info!("Connected to Redis for ACL operations"),
            Ok(Err(e)) => return Err(AppError::from(e)),
            Err(_) => {
                return Err(AppError::ConfigError(
                    "Timeout during Redis connection initialization".into(),
                ))
            }
        }

        // Determine ACL categories from role
        // Simple mapping: if role contains "write" -> grant @write; if "read" -> @read
        let mut acl_args: Vec<String> = vec!["SETUSER".to_string(), role.to_string()];

        // enable user and set password
        acl_args.push("on".to_string());
        acl_args.push(format!(">{}", encoded_password));
        // allow keys pattern
        acl_args.push("~*".to_string());

        if role.contains("write") && role.contains("read") {
            acl_args.push("+@all".to_string());
        } else if role.contains("write") {
            acl_args.push("+@write".to_string());
            acl_args.push("+@read".to_string());
        } else if role.contains("read") {
            acl_args.push("+@read".to_string());
        } else {
            // fallback to read-only
            acl_args.push("+@read".to_string());
        }

        // disallow dangerous/admin commands
        acl_args.push("-@admin".to_string());

        // Execute ACL SETUSER via EVAL (use Redis Lua to call ACL since fred doesn't expose ACL helper)
        let lua_script = "return redis.call('ACL','SETUSER', unpack(ARGV))";
        let eval_args: Vec<String> = acl_args[1..].to_vec();

        match client
            .eval::<String, _, _, _>(lua_script, Vec::<String>::new(), eval_args)
            .await
        {
            Ok(_) => {
                tracing::info!(operation = "create_user", username = %acl_args[1], target = "redis", ttl_seconds = ttl_seconds, "Redis ACL SETUSER executed");
                Ok(GeneratedCredential {
                    username: acl_args[1].clone(),
                    secret: Zeroizing::new(encoded_password),
                    ttl_seconds,
                })
            }
            Err(_) => Err(redis_acl_error("create_user", &acl_args[1])),
        }
    }

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError> {
        // Connect to admin Redis and remove the user
        let url = Url::parse(target_conn_str).map_err(|_| {
            AppError::Internal("Invalid Redis connection string format".into())
        })?;

        let host = url.host_str().ok_or_else(|| {
            AppError::Internal("Redis connection string missing host".into())
        })?;
        let port = url.port().unwrap_or(6379);
        let admin_password = url.password().map(|s| s.to_string());
        let db_index: u8 = url.path().trim_start_matches('/').parse().unwrap_or(0);

        let reconnect_policy = ReconnectPolicy::new_exponential(0, 100, 5000, 2);

        let redis_config = Config {
            server: ServerConfig::Centralized {
                server: Server::new(host, port),
            },
            password: admin_password,
            database: Some(db_index),
            ..Default::default()
        };

        let perf_config = PerformanceConfig::default();

        let client = Client::new(redis_config, Some(perf_config), None, Some(reconnect_policy));
        client.connect();

        match tokio::time::timeout(Duration::from_secs(5), client.wait_for_connect()).await {
            Ok(Ok(_)) => tracing::info!("Connected to Redis for ACL revoke"),
            Ok(Err(e)) => return Err(AppError::from(e)),
            Err(_) => {
                return Err(AppError::ConfigError(
                    "Timeout during Redis connection initialization".into(),
                ))
            }
        }

        // Prefer to delete the user via ACL DELUSER; use EVAL to issue the command.
        let del_script = "return redis.call('ACL','DELUSER', ARGV[1])";
        if client
            .eval::<i64, _, _, _>(del_script, Vec::<String>::new(), vec![username.to_string()])
            .await
            .is_err()
        {
            // fallback: disable the user
            let disable_script = "return redis.call('ACL','SETUSER', ARGV[1], 'off')";
            client
                .eval::<String, _, _, _>(disable_script, Vec::<String>::new(), vec![username.to_string()])
                .await
                .map_err(|_| redis_acl_error("drop_user", username))?;
        }

        tracing::info!(operation = "drop_user", username = %username, target = "redis", "Redis ACL user removed");

        Ok(())
    }
}
