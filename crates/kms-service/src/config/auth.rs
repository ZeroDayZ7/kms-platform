use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// List of exact path prefixes that are considered public and bypass HMAC verification.
    /// Example: ["/health", "/status"]
    pub public_endpoints: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            public_endpoints: vec!["/health".to_string(), "/status".to_string()],
        }
    }
}
