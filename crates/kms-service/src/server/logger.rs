use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::{LogConfig, LogFormat};

pub fn init_logging(config: &LogConfig) {
    let default_filter = format!(
        "{},hyper=warn,reqwest=warn,h2=warn,tower_http=warn,axum=warn",
        config.level.as_ref()
    );
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let console_layer = match config.format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_span_list(false)
            .with_writer(std::io::stdout)
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
            .with_target(false)
            .boxed(),

        LogFormat::Compact | LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .compact()
            .with_writer(std::io::stdout)
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
                "%H:%M:%S".to_string(),
            ))
            .with_ansi(true)
            .with_target(false)
            .with_file(false)
            .with_line_number(false)
            .boxed(),
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .init();
}
