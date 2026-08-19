use super::acl::AclSettings;
use super::cors::CorsConfig;
use super::database::DatabaseConfig;
use super::log::LogConfig;
use super::rate_limit::RateLimitConfig;
use super::redis::RedisConfig;
use super::server::ServerConfig;
use crate::config::crypto::CryptoSettings;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub cors: CorsConfig,
    pub redis: RedisConfig,
    pub database: DatabaseConfig,
    pub rate_limit: RateLimitConfig,
    pub crypto: CryptoSettings,
    pub acl: AclSettings,
}
