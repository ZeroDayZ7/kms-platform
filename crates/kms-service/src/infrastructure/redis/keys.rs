use crate::domain::value_objects::client_ip::ClientIp;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisKey(String);

impl RedisKey {
    /// Klucz pod rate limiter oparty o IP klienta oraz konkretną ścieżkę (np. "/api/v1/encrypt")
    pub fn rate_limit(path: &str, ip: &ClientIp) -> Self {
        let clean_path = path.trim_start_matches('/');
        Self(format!("rl:{clean_path}:{}", ip.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RedisKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for RedisKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for RedisKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
