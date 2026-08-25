use kms_service::config::RedisConfig;
use serde::Deserialize;

//# region redis_config_defaults_enabled_to_true
#[test]
//#region redis_config_defaults_enabled_to_true
fn redis_config_defaults_enabled_to_true() {
    #[derive(Debug, Deserialize)]
    struct TestConfig {
        #[serde(default)]
        redis: RedisConfig,
    }

    let config: TestConfig = toml::from_str(
        r#"
        [redis]
        host = "127.0.0.1"
        port = 6379
        db = 0
        "#,
    )
    .expect("config should deserialize with default enabled=true");

    assert!(config.redis.enabled);
}
//# endregion
