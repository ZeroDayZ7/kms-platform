use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub name: String,
    pub pool_size: u32,
    pub auth_source: Option<String>,
}
