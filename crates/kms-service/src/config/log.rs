// src/config/log.rs
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Trace,
}

impl AsRef<str> for LogLevel {
    fn as_ref(&self) -> &str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Trace => "trace",
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    pub level: LogLevel,
}
