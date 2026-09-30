use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub enum SpiffeIdentityMode {
    #[default]
    Authoritative,
    FileFallback,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SpiffeConfig {
    pub enabled: bool,
    pub trust_domain: Option<String>,
    pub workload_id: Option<String>,
    pub spire_agent_socket_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub trust_bundle_path: Option<String>,
    pub rotation_interval_secs: Option<u64>,
    #[serde(default)]
    pub identity_mode: SpiffeIdentityMode,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// List of exact path prefixes that are considered public and bypass HMAC verification.
    /// Example: ["/health", "/status"]
    pub public_endpoints: Vec<String>,
    #[serde(default)]
    pub spiffe: SpiffeConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            public_endpoints: vec!["/health".to_string(), "/status".to_string()],
            spiffe: SpiffeConfig::default(),
        }
    }
}
