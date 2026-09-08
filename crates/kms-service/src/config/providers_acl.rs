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

// Expect only the wrapped format now:
// { "providers_acl": { "services": { ... } } }
#[derive(Deserialize)]
struct ProvidersAclWrapped {
    providers_acl: ProvidersAclInner,
}

#[derive(Deserialize)]
struct ProvidersAclInner {
    services: HashMap<String, ProviderPolicy>,
}

impl<'de> Deserialize<'de> for ProvidersAclSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapped = ProvidersAclWrapped::deserialize(deserializer)
            .map_err(|e| serde::de::Error::custom(format!("providers_acl: invalid format - expected '{{ \"providers_acl\": {{ \"services\": {{ ... }} }} }}' - {e}")))?;

        Ok(ProvidersAclSettings {
            services: wrapped.providers_acl.services,
        })
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
