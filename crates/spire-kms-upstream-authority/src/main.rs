mod config;
mod grpc_server;
mod kms_client;

#[cfg(unix)]
use std::io::{self, Write};

use clap::Parser;
use config::PluginArgs;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter("spire_kms_upstream_authority=trace,tonic=trace,hyper=trace")
        .with_target(false)
        .without_time()
        .init();
}

#[cfg(unix)]
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
        spire_plugin_socket = %config.spire_plugin_socket_path,
        kms_socket = %config.kms_socket_path,
        ca_tag = %config.ca_tag,
        "Starting SPIRE upstream authority shim"
    );

    #[cfg(unix)]
    {
        tracing::debug!(
            spire_plugin_socket = %config.spire_plugin_socket_path,
            "Preparing SPIRE plugin socket before handshake"
        );

        grpc_server::prepare_plugin_socket_path(&config.spire_plugin_socket_path).await?;

        let listener = tokio::net::UnixListener::bind(&config.spire_plugin_socket_path)?;
        tracing::info!(
            spire_plugin_socket = %config.spire_plugin_socket_path,
            "SPIRE plugin socket bound successfully"
        );

        tracing::debug!(
            spire_plugin_socket = %config.spire_plugin_socket_path,
            "Emitting go-plugin handshake on stdout"
        );
        emit_go_plugin_handshake(&config.spire_plugin_socket_path)?;
        tracing::debug!(
            spire_plugin_socket = %config.spire_plugin_socket_path,
            "go-plugin handshake emitted"
        );

        grpc_server::serve_with_listener(config, listener).await
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
