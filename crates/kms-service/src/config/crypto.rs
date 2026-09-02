use serde::{Deserialize, Deserializer};
use std::ops::Deref;
use std::time::Duration;

// --- TYPY DEDYKOWANE (NewTypes z walidacją) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTtlDays(pub u64);

impl Deref for KeyTtlDays {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyTtlDays {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = u64::deserialize(deserializer)?;
        if !(1..=3650).contains(&val) {
            return Err(serde::de::Error::custom(
                "key_ttl_days must be between 1 and 3650 days",
            ));
        }
        Ok(KeyTtlDays(val))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracePeriodMinutes(pub i64);

impl Deref for GracePeriodMinutes {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GracePeriodMinutes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = i64::deserialize(deserializer)?;
        if !(1..=10_080).contains(&val) {
            return Err(serde::de::Error::custom(
                "grace_period_minutes must be between 1 and 10080 minutes (max 7 days)",
            ));
        }
        Ok(GracePeriodMinutes(val))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheCleanupIntervalSecs(pub u64);

impl Deref for CacheCleanupIntervalSecs {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<CacheCleanupIntervalSecs> for Duration {
    fn from(val: CacheCleanupIntervalSecs) -> Self {
        Duration::from_secs(val.0)
    }
}

impl<'de> Deserialize<'de> for CacheCleanupIntervalSecs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = u64::deserialize(deserializer)?;
        if !(1..=86_400).contains(&val) {
            return Err(serde::de::Error::custom(
                "cache_cleanup_interval_secs must be between 1 second and 86400 seconds (24h)",
            ));
        }
        Ok(CacheCleanupIntervalSecs(val))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirationCheckIntervalSecs(pub u64);

impl Deref for ExpirationCheckIntervalSecs {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ExpirationCheckIntervalSecs> for Duration {
    fn from(val: ExpirationCheckIntervalSecs) -> Self {
        Duration::from_secs(val.0)
    }
}

impl<'de> Deserialize<'de> for ExpirationCheckIntervalSecs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = u64::deserialize(deserializer)?;
        if !(1..=86_400).contains(&val) {
            return Err(serde::de::Error::custom(
                "expiration_check_interval_secs must be between 1 second and 86400 seconds (24h)",
            ));
        }
        Ok(ExpirationCheckIntervalSecs(val))
    }
}

// --- STRUKTURA KONFIGURACJI VHSM (PURE CLIENT) ---

#[derive(Debug, Deserialize, Clone)]
pub struct CryptoSettings {
    #[serde(default = "default_hsm_socket_path")]
    pub hsm_socket_path: String,
    pub current_master_key_version: i32,
    pub default_key_ttl_days: KeyTtlDays,
    pub grace_period_minutes: GracePeriodMinutes,
    #[serde(default = "default_hsm_timeout_secs")]
    pub hsm_timeout_secs: u64,
    #[serde(default)]
    pub enable_http_rewrap: bool,
    #[serde(default = "default_cache_cleanup_interval_secs")]
    pub cache_cleanup_interval_secs: CacheCleanupIntervalSecs,
    #[serde(default = "default_expiration_check_interval_secs")]
    pub expiration_check_interval_secs: ExpirationCheckIntervalSecs,
}

impl CryptoSettings {
    pub fn cache_cleanup_duration(&self) -> Duration {
        self.cache_cleanup_interval_secs.into()
    }

    pub fn expiration_check_duration(&self) -> Duration {
        self.expiration_check_interval_secs.into()
    }
}

fn default_hsm_socket_path() -> String {
    "/run/vhsm/vhsm.sock".to_string()
}

fn default_hsm_timeout_secs() -> u64 {
    5
}

fn default_cache_cleanup_interval_secs() -> CacheCleanupIntervalSecs {
    CacheCleanupIntervalSecs(60)
}

fn default_expiration_check_interval_secs() -> ExpirationCheckIntervalSecs {
    ExpirationCheckIntervalSecs(300)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_settings_deserialization() {
        let toml_data = r#"
            hsm_socket_path = "/run/vhsm/vhsm.sock"
            current_master_key_version = 1
            default_key_ttl_days = 365
            grace_period_minutes = 30
            enable_http_rewrap = false
        "#;

        let settings: CryptoSettings = toml::from_str(toml_data).unwrap();
        assert_eq!(settings.hsm_socket_path, "/run/vhsm/vhsm.sock");
        assert_eq!(settings.current_master_key_version, 1);
        assert_eq!(*settings.default_key_ttl_days, 365);
        assert_eq!(*settings.grace_period_minutes, 30);
        assert_eq!(*settings.cache_cleanup_interval_secs, 60);
        assert_eq!(*settings.expiration_check_interval_secs, 300);
        assert_eq!(settings.cache_cleanup_duration(), Duration::from_secs(60));
        assert_eq!(
            settings.expiration_check_duration(),
            Duration::from_secs(300)
        );
    }
}
