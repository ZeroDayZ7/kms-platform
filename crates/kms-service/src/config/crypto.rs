use serde::{Deserialize, Deserializer};
use std::ops::Deref;

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

// --- STRUKTURA KONFIGURACJI VHSM (PURE CLIENT) ---

#[derive(Debug, Deserialize, Clone)]
pub struct CryptoSettings {
    #[serde(default = "default_hsm_socket_path")]
    pub hsm_socket_path: String,
    pub current_master_key_version: i32,
    pub default_key_ttl_days: KeyTtlDays,
    pub grace_period_minutes: GracePeriodMinutes,
    #[serde(default)]
    pub enable_http_rewrap: bool,
}

fn default_hsm_socket_path() -> String {
    "/run/vhsm/vhsm.sock".to_string()
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
    }
}
