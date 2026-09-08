use serde::Deserialize;
use serde::de::Deserializer;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderConstraints {
    pub max_ttl_seconds: Option<i64>,
    pub default_ttl_seconds: Option<i64>,
    pub redis_acl_rules: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderPolicy {
    pub constraints: ProviderConstraints,
}

#[derive(Debug, Clone, Default)]
pub struct ProvidersAclSettings {
    pub services: HashMap<String, ProviderPolicy>,
}

// Backwards-compatible deserialization: accept either
// { "services": { ... } }
// or { "providers_acl": { "services": { ... } } }
#[derive(Deserialize)]
struct ProvidersAclDirect {
    services: HashMap<String, ProviderPolicy>,
}

#[derive(Deserialize)]
struct ProvidersAclWrapped {
    providers_acl: ProvidersAclDirect,
}

impl<'de> Deserialize<'de> for ProvidersAclSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        if let Ok(direct) = ProvidersAclDirect::deserialize(v.clone()) {
            return Ok(ProvidersAclSettings {
                services: direct.services,
            });
        }

        if let Ok(wrapped) = ProvidersAclWrapped::deserialize(v) {
            return Ok(ProvidersAclSettings {
                services: wrapped.providers_acl.services,
            });
        }

        Err(serde::de::Error::custom(
            "providers_acl: invalid format - expected either 'services' or 'providers_acl.services'",
        ))
    }
}

impl ProvidersAclSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.services.is_empty() {
            return Err("providers_acl.json contains no services".to_string());
        }

        for (name, policy) in &self.services {
            if policy.constraints.redis_acl_rules.is_none() {
                return Err(format!("service '{}' missing 'redis_acl_rules'", name));
            }

            if let (Some(def), Some(max)) = (
                policy.constraints.default_ttl_seconds,
                policy.constraints.max_ttl_seconds,
            ) {
                if def <= 0 || max <= 0 {
                    return Err(format!("ttl values for '{}' must be > 0", name));
                }
                if def > max {
                    return Err(format!(
                        "default_ttl_seconds > max_ttl_seconds for '{}'",
                        name
                    ));
                }
            }
        }

        Ok(())
    }
}
