#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub socket_path: String,
    pub ca_tag: String,
    pub plugin_name: String,
}
