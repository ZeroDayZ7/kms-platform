mod config;
mod grpc_server;

use std::io::{self, Read, Write};

use clap::Parser;

use crate::{config::PluginConfig, grpc_server::serve};

#[derive(Debug, Parser)]
#[command(
    name = "spire-kms-upstream-authority",
    about = "SPIRE upstream authority shim for KMS"
)]
struct Args {
    #[arg(long, env = "KMS_GRPC_SOCKET", default_value = "/run/kms/kms.sock")]
    socket: String,

    #[arg(long, env = "KMS_CA_TAG", default_value = "root")]
    ca_tag: String,
}

fn run_go_plugin_handshake() -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut buffer = [0_u8; 1];
    let _ = stdin.read_exact(&mut buffer);

    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{{\"protocolVersion\":1,\"pluginName\":\"spire-kms-upstream-authority\",\"pluginType\":\"UpstreamAuthority\"}}"
    )?;
    stdout.flush()?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();
    let config = PluginConfig {
        socket_path: args.socket,
        ca_tag: args.ca_tag,
        plugin_name: "spire-kms-upstream-authority".to_string(),
    };

    tracing::info!(
        plugin = %config.plugin_name,
        socket = %config.socket_path,
        ca_tag = %config.ca_tag,
        "Starting SPIRE upstream authority shim"
    );

    if let Err(err) = run_go_plugin_handshake() {
        tracing::warn!(error = %err, "go-plugin handshake did not complete; continuing with the shim loop");
    }

    serve(config).await
}
