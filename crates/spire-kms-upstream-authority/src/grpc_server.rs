#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use tonic_health::ServingStatus;

use tonic::{Request, Response, Status};

use crate::{
    config::PluginConfig,
    kms_client::{KmsSignRequest, sign_csr_via_kms},
};

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

        tracing::info!(
            kms_socket = %self.config.kms_socket_path,
            ca_tag = %self.config.ca_tag,
            csr_len = req.csr_pem.len(),
            "MintX509CA request received from SPIRE"
        );

        let ca_tag = if req.ca_tag.trim().is_empty() {
            self.config.ca_tag.clone()
        } else {
            req.ca_tag.clone()
        };

        let response = sign_csr_via_kms(
            &self.config.kms_socket_path,
            KmsSignRequest {
                csr_pem: req.csr_pem,
                ca_tag,
                validity_days: 3650,
                caller_service: "spire".to_string(),
            },
        )
        .await
        .map_err(|err| Status::unavailable(format!("kms-service proxy failed: {err}")))?;

        let mut chain = Vec::new();
        if !response.certificate_pem.trim().is_empty() {
            chain.push(response.certificate_pem);
        }
        if let Some(root) = response.root_certificate_pem
            && !root.trim().is_empty()
        {
            chain.push(root);
        }

        if chain.is_empty() {
            return Err(Status::internal(
                "kms-service returned an empty certificate chain",
            ));
        }

        Ok(Response::new(MintX509caResponse {
            x509_ca_chain: chain,
        }))
    }
}

#[cfg(unix)]
pub async fn prepare_plugin_socket_path(socket_path: &str) -> anyhow::Result<()> {
    let socket = Path::new(socket_path);

    if let Some(parent) = socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if socket.exists() {
        tokio::fs::remove_file(socket).await?;
    }

    Ok(())
}

#[cfg(unix)]
async fn cleanup_socket_file(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();
    if path.exists() {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[cfg(unix)]
pub async fn serve_with_listener(
    config: PluginConfig,
    listener: tokio::net::UnixListener,
) -> anyhow::Result<()> {
    let socket_path = config.spire_plugin_socket_path.clone();
    let service = UpstreamAuthorityService {
        config: Arc::new(config),
    };

    tracing::info!(
        "Serving SPIRE UpstreamAuthority on plugin socket {}",
        socket_path
    );

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_service_status("", ServingStatus::Serving).await;
    health_reporter
        .set_service_status(
            "spire.server.upstreamauthority.v1.UpstreamAuthority",
            ServingStatus::Serving,
        )
        .await;

    tracing::debug!(
        service_count = 2,
        "Configured tonic server with UpstreamAuthorityServer and health_service"
    );

    let server = tonic::transport::Server::builder()
        .add_service(generated::upstream_authority_server::UpstreamAuthorityServer::new(service))
        .add_service(health_service);

    tokio::select! {
        result = server.serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal, cleaning up SPIRE plugin socket");
            cleanup_socket_file(&socket_path).await;
        }
    }

    Ok(())
}

#[cfg(unix)]
pub async fn serve(config: PluginConfig) -> anyhow::Result<()> {
    prepare_plugin_socket_path(&config.spire_plugin_socket_path).await?;

    let listener = tokio::net::UnixListener::bind(&config.spire_plugin_socket_path)?;
    std::fs::set_permissions(
        &config.spire_plugin_socket_path,
        std::fs::Permissions::from_mode(0o660),
    )?;

    serve_with_listener(config, listener).await
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub async fn serve(_config: PluginConfig) -> anyhow::Result<()> {
    anyhow::bail!(
        "SPIRE upstream authority Unix Domain Socket support is only available on Unix-like systems; this host is {}",
        std::env::consts::OS
    )
}
