use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: IpAddr,
    pub port: u16,
    pub shutdown_timeout: u64,
}
