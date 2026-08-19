use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub global_per_second: u64,
    pub global_burst: u32,
    pub health_per_second: u64,
    pub health_burst: u32,
    pub auth_per_second: u64,
    pub auth_burst: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitTier {
    Global,
    Auth,
    Health,
}

impl RateLimitTier {
    /// Mapuje ścieżkę na kategorię limitu
    pub fn from_path(path: &str) -> Self {
        if path.starts_with("/auth") {
            Self::Auth
        } else if path.starts_with("/health") {
            Self::Health
        } else {
            Self::Global
        }
    }

    /// Wyciąga konkretne wartości z Twojej struktury configu
    pub fn get_limits(&self, config: &RateLimitConfig) -> (u64, u64) {
        match self {
            Self::Global => (config.global_burst as u64, config.global_per_second),
            Self::Auth => (config.auth_burst as u64, config.auth_per_second),
            Self::Health => (config.health_burst as u64, config.health_per_second),
        }
    }
}
