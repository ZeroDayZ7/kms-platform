use super::acl::AclSettings;
use super::auth::AuthConfig;
use super::cors::CorsConfig;
use super::database::DatabaseConfig;
use super::log::LogConfig;
use super::rate_limit::RateLimitConfig;
use super::redis::RedisConfig;
use super::server::ServerConfig;
use crate::config::crypto::CryptoSettings;
use serde::Deserialize;
use crate::config::ProvidersAclSettings;

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
    pub auth: AuthConfig,
    pub providers_acl: ProvidersAclSettings,
}
