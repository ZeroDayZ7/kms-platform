use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

//# region default_enabled
fn default_enabled() -> bool {
    true
}
//# endregion

impl Default for RedisConfig {
    //# region default
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
            password: None,
            db: 0,
            enabled: default_enabled(),
        }
    }
    //# endregion
}
