use crate::errors::AppResult;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, limit: u64, window_sec: u64) -> AppResult<RateLimitStatus>;
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
