mod config;
mod grpc_server;
mod kms_client;

use std::io::{self, Write};

use clap::Parser;
use config::PluginArgs;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter("info")
        .with_target(false)
        .without_time()
        .init();
}

fn emit_go_plugin_handshake(socket_path: &str) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "1|1|unix|{socket_path}|grpc")?;
    stdout.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let args = PluginArgs::parse();
    let config = args.into_config();
    config.validate()?;

    tracing::info!(
        plugin = %config.plugin_name,
        socket = %config.socket_path,
        ca_tag = %config.ca_tag,
        "Starting SPIRE upstream authority shim"
    );

    emit_go_plugin_handshake(&config.socket_path)?;

    #[cfg(unix)]
    {
        grpc_server::serve(config).await
    }

    #[cfg(not(unix))]
    {
        eprintln!(
            "SPIRE upstream authority requires Unix Domain Sockets; this host is {}.",
            std::env::consts::OS
        );
        Ok(())
    }
}
