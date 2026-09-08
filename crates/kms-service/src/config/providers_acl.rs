use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProviderConstraints {
    #[serde(default)]
    pub max_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub default_ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisProviderConfig {
    #[serde(default)]
    pub acl_rules: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProviderPolicy {
    #[serde(default)]
    pub constraints: ProviderConstraints,
    #[serde(default)]
    pub redis: Option<RedisProviderConfig>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProvidersAclSettings {
    #[serde(default)]
    pub services: HashMap<String, ProviderPolicy>,
}

impl ProvidersAclSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.services.is_empty() {
            return Err("providers_acl.json contains no services".to_string());
        }

        for (name, policy) in &self.services {
            if let Some(def) = policy.constraints.default_ttl_seconds
                && def <= 0
            {
                return Err(format!("default_ttl_seconds for '{}' must be > 0", name));
            }

            if let Some(max) = policy.constraints.max_ttl_seconds
                && max <= 0
            {
                return Err(format!("max_ttl_seconds for '{}' must be > 0", name));
            }

            if let (Some(def), Some(max)) = (
                policy.constraints.default_ttl_seconds,
                policy.constraints.max_ttl_seconds,
            ) && def > max
            {
                return Err(format!(
                    "default_ttl_seconds > max_ttl_seconds for '{}'",
                    name
                ));
            }

            if let Some(redis) = &policy.redis
                && redis.acl_rules.is_empty()
            {
                return Err(format!("service '{}' has empty redis.acl_rules", name));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deserializes_direct_services_object() {
        let value = json!({
            "services": {
                "auth-service": {
                    "constraints": {
                        "max_ttl_seconds": 86400,
                        "default_ttl_seconds": 900
                    },
                    "redis": {
                        "acl_rules": ["on", "+@read", "~cache:auth:*"]
                    }
                }
            }
        });

        let settings: ProvidersAclSettings = serde_json::from_value(value).unwrap();
        assert!(settings.services.contains_key("auth-service"));
        assert!(settings.services["auth-service"].redis.is_some());
    }

    #[test]
    fn validates_service_without_redis_specific_config() {
        let value = json!({
            "services": {
                "postgres-service": {
                    "constraints": {
                        "max_ttl_seconds": 86400,
                        "default_ttl_seconds": 900
                    }
                }
            }
        });

        let settings: ProvidersAclSettings = serde_json::from_value(value).unwrap();
        settings.validate().unwrap();
    }

    #[test]
    fn rejects_wrapped_providers_acl_object() {
        let value = json!({
            "providers_acl": {
                "services": {
                    "gateway-service": {
                        "constraints": {
                            "max_ttl_seconds": 7200,
                            "default_ttl_seconds": 1800
                        },
                        "redis": {
                            "acl_rules": ["on", "+@read", "+ping"]
                        }
                    }
                }
            }
        });

        let settings: ProvidersAclSettings = serde_json::from_value(value).unwrap();
        assert!(settings.validate().is_err());
    }
}
