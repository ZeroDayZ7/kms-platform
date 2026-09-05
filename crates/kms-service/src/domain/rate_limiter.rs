use crate::errors::{AppError, AppResult};
use crate::infrastructure::redis::client::RedisManager;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, limit: u64, window_sec: u64) -> AppResult<RateLimitStatus>;
}

#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn mark_used(&self, key: &str, ttl_sec: u64) -> AppResult<bool>;
}

#[derive(Clone)]
pub struct RedisNonceStore {
    redis: Arc<RedisManager>,
}

impl RedisNonceStore {
    pub fn new(redis: Arc<RedisManager>) -> Self {
        Self { redis }
    }
}

#[async_trait]
impl NonceStore for RedisNonceStore {
    async fn mark_used(&self, key: &str, ttl_sec: u64) -> AppResult<bool> {
        self.redis.set_if_not_exists(key, "1", ttl_sec).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitStatus {
    pub allowed: bool,
    pub current: u64,
}

#[derive(Default, Clone)]
pub struct InMemoryRateLimiter {
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl InMemoryRateLimiter {
    //# region new
    //#region new
    pub fn new() -> Self {
        Self::default()
    }
    //# endregion
}

#[derive(Default, Clone)]
pub struct InMemoryNonceStore {
    used: Arc<Mutex<HashMap<String, Instant>>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn mark_used(&self, key: &str, ttl_sec: u64) -> AppResult<bool> {
        let now = Instant::now();
        let ttl = Duration::from_secs(ttl_sec.max(1));
        let mut used = self
            .used
            .lock()
            .map_err(|_| AppError::Internal("In-memory nonce cache is poisoned".into()))?;

        used.retain(|_, timestamp| now.duration_since(*timestamp) <= ttl);
        if used.contains_key(key) {
            return Ok(false);
        }

        used.insert(key.to_string(), now);
        Ok(true)
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    //# region check
    async fn check(&self, key: &str, limit: u64, window_sec: u64) -> AppResult<RateLimitStatus> {
        let now = Instant::now();
        let window = Duration::from_secs(window_sec.max(1));
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = buckets.entry(key.to_string()).or_default();

        entries.retain(|timestamp| now.duration_since(*timestamp) <= window);

        let current = entries.len() as u64;
        let allowed = current < limit;

        if allowed {
            entries.push_back(now);
        }

        Ok(RateLimitStatus {
            allowed,
            current: current + u64::from(allowed),
        })
    }
    //# endregion
}
