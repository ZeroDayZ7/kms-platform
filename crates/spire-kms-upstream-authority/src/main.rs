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
    let mut stdout = io::stdout();
    let handshake = format!("1|1|unix|{socket_path}|grpc\n");
    stdout.write_all(handshake.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    tracing::info!(
        "PLUGIN_START_BEGIN name=spire-kms-upstream-authority"
    );
    tracing::info!(
        "RUST_LOG_FILTER_ACTIVE level=trace target=all"
    );

    let args = PluginArgs::parse();
    tracing::info!(
        plugin_args = ?args,
        "PLUGIN_ARGS_PARSED"
    );

    let config = args.into_config();
    tracing::info!(
        plugin_name = %config.plugin_name,
        spire_plugin_socket = %config.spire_plugin_socket_path,
        kms_socket = %config.kms_socket_path,
        ca_tag = %config.ca_tag,
        "PLUGIN_CONFIG_RAW"
    );

    config.validate()?;
    tracing::info!(
        plugin = %config.plugin_name,
        spire_plugin_socket = %config.spire_plugin_socket_path,
        kms_socket = %config.kms_socket_path,
        ca_tag = %config.ca_tag,
        "PLUGIN_CONFIG_VALIDATED"
    );
    tracing::info!(
        "PLUGIN_CONFIG_OK spire_socket={} kms_socket={} ca_tag={}",
        config.spire_plugin_socket_path,
        config.kms_socket_path,
        config.ca_tag
    );

    #[cfg(unix)]
    {
        tracing::info!(
            "PLUGIN_SOCKET_PREPARE path={}",
            config.spire_plugin_socket_path
        );
        let result = grpc_server::serve(config).await;
        tracing::info!(
            server_result = ?result,
            "PLUGIN_SERVER_EXIT"
        );
        result
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
