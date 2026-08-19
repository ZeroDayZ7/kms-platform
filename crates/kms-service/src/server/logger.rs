use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

pub fn init_logging<S: AsRef<str>>(level: S) {
    let level_ref = level.as_ref();

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level_ref));

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
        .with_ansi(true)
        .with_target(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .init();
}
