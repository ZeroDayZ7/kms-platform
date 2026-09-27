use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::config::PluginConfig;

mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/spire.server.upstreamauthority.v1.rs"
    ));
}

use generated::{
    MintX509caRequest, MintX509caResponse, upstream_authority_server::UpstreamAuthority,
};

#[derive(Clone)]
pub struct UpstreamAuthorityService {
    pub config: Arc<PluginConfig>,
}

#[tonic::async_trait]
impl UpstreamAuthority for UpstreamAuthorityService {
    async fn mint_x509ca(
        &self,
        request: Request<MintX509caRequest>,
    ) -> Result<Response<MintX509caResponse>, Status> {
        let req = request.into_inner();

        #[cfg(unix)]
        let socket_exists = std::path::Path::new(&self.config.socket_path).exists();
        #[cfg(not(unix))]
        let socket_exists = false;

        tracing::info!(
            socket = %self.config.socket_path,
            ca_tag = %self.config.ca_tag,
            csr_len = req.csr_pem.len(),
            "Received SPIRE MintX509CA request"
        );

        if !socket_exists {
            return Err(Status::unavailable(format!(
                "KMS socket not available at {}: SPIRE upstream authority is waiting for kms-service to bind the UDS",
                self.config.socket_path
            )));
        }

        Ok(Response::new(MintX509caResponse {
            x509_ca_chain: vec![req.csr_pem, format!("root-cert:{}", self.config.ca_tag)],
        }))
    }
}

#[cfg(unix)]
pub async fn serve(config: PluginConfig) -> anyhow::Result<()> {
    use std::path::Path;

    let socket_path = config.socket_path.clone();
    let socket = Path::new(&socket_path);

    if let Some(parent) = socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if socket.exists() {
        tokio::fs::remove_file(&socket_path).await.ok();
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;

    let service = UpstreamAuthorityService {
        config: Arc::new(config),
    };

    tracing::info!(
        "Serving SPIRE UpstreamAuthority over Unix Domain Socket at {}",
        socket_path
    );

    tonic::transport::Server::builder()
        .add_service(generated::upstream_authority_server::UpstreamAuthorityServer::new(service))
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
        .await?;

    Ok(())
}

#[cfg(not(unix))]
pub async fn serve(_config: PluginConfig) -> anyhow::Result<()> {
    anyhow::bail!(
        "SPIRE upstream authority Unix Domain Socket support is only available on Unix-like systems; this host is {}",
        std::env::consts::OS
    )
}
