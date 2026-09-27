use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "spire-kms-upstream-authority",
    about = "SPIRE upstream authority shim for KMS"
)]
pub struct PluginArgs {
    #[arg(long, env = "KMS_GRPC_SOCKET", default_value = "/run/kms/kms.sock")]
    pub socket: String,

    #[arg(long, env = "KMS_CA_TAG", default_value = "root")]
    pub ca_tag: String,
}

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub socket_path: String,
    pub ca_tag: String,
    pub plugin_name: String,
}

impl PluginArgs {
    pub fn into_config(self) -> PluginConfig {
        PluginConfig {
            socket_path: self.socket,
            ca_tag: self.ca_tag,
            plugin_name: "spire-kms-upstream-authority".to_string(),
        }
    }
}

impl PluginConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.socket_path.trim().is_empty() {
            anyhow::bail!("socket path must not be empty");
        }

        if self.ca_tag.trim().is_empty() {
            anyhow::bail!("CA tag must not be empty");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::PluginArgs;

    #[test]
    fn parses_socket_and_ca_tag() {
        let args = PluginArgs::try_parse_from([
            "spire-kms-upstream-authority",
            "--socket",
            "/tmp/test-kms.sock",
            "--ca-tag",
            "custom-root",
        ])
        .expect("valid CLI args");

        let config = args.into_config();

        assert_eq!(config.socket_path, "/tmp/test-kms.sock");
        assert_eq!(config.ca_tag, "custom-root");
        assert_eq!(config.plugin_name, "spire-kms-upstream-authority");
    }
}
