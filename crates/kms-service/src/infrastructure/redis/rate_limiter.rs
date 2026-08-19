use crate::domain::rate_limiter::{RateLimitStatus, RateLimiter};
use crate::errors::AppResult;
use crate::infrastructure::redis::client::RedisManager;
use async_trait::async_trait;
use fred::interfaces::LuaInterface;
use std::sync::Arc;
use tracing::warn;

const LUA_SCRIPT: &str = include_str!("../scripts/redis_rate_limit.lua");

#[derive(Clone)]
pub struct RedisRateLimiter {
    redis: Arc<RedisManager>,
    script_hash: String,
}

impl RedisRateLimiter {
    //# region new
    pub async fn new(redis: Arc<RedisManager>) -> Self {
        let client = redis.client();

        let script_hash = match client.script_load(LUA_SCRIPT).await {
            Ok(hash) => hash,
            Err(e) => {
                warn!(
                    "⚠️ Nie udało się załadować skryptu: {}. Fallback do EVAL.",
                    e
                );
                String::new()
            }
        };

        Self { redis, script_hash }
    }
    //# endregion

    //# region fallback_eval
    async fn fallback_eval(&self, key: &str, args: Vec<String>) -> AppResult<i64> {
        let res = self
            .redis
            .client()
            .eval::<i64, _, _, _>(LUA_SCRIPT, vec![key], args)
            .await?;

        Ok(res)
    }
    //# endregion
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    //# region check
    async fn check(&self, key: &str, limit: u64, window_sec: u64) -> AppResult<RateLimitStatus> {
        let client = self.redis.client();
        let args = vec![window_sec.to_string()];

        let result: i64 = if !self.script_hash.is_empty() {
            match client
                .evalsha::<i64, _, _, _>(&self.script_hash, vec![key], args.clone())
                .await
            {
                Ok(res) => res,
                Err(_) => self.fallback_eval(key, args).await?,
            }
        } else {
            self.fallback_eval(key, args).await?
        };

        Ok(RateLimitStatus {
            allowed: result as u64 <= limit,
            current: result as u64,
        })
    }
    //# endregion
}
