#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use tonic_health::ServingStatus;

use tokio::sync::Mutex as AsyncMutex;
use tonic::{Request, Response, Status};

// Simplify complex channel sender types for Clippy
type StdioSender = tokio::sync::mpsc::Sender<Result<StdioData, Status>>;
type ConnSender = tokio::sync::mpsc::Sender<Result<ConnInfo, Status>>;

use crate::{
    config::PluginConfig,
    kms_client::{KmsSignRequest, sign_csr_via_kms},
};

mod generated {
    pub mod plugin {
        tonic::include_proto!("plugin");
    }
    pub mod spire {
        pub mod common {
            pub mod plugin {
                tonic::include_proto!("spire.common.plugin");
            }
        }
        pub mod config {
            pub mod v1 {
                tonic::include_proto!("spire.config.v1");
            }
        }
        pub mod plugin {
            pub mod server {
                pub mod upstreamauthority {
                    pub mod v1 {
                        tonic::include_proto!("spire.plugin.server.upstreamauthority.v1");
                    }
                }
            }
            pub mod types {
                tonic::include_proto!("spire.plugin.types");
            }
        }
        pub mod service {
            pub mod private {
                pub mod init {
                    pub mod v1 {
                        tonic::include_proto!("spire.service.private.init.v1");
                    }
                }
            }
        }
    }
}

#[allow(unused_imports)]
use generated::plugin::{
    ConnInfo, Empty, StdioData,
    grpc_broker_server::{GrpcBroker, GrpcBrokerServer},
    grpc_controller_server::{GrpcController, GrpcControllerServer},
    grpc_stdio_server::{GrpcStdio, GrpcStdioServer},
};
#[allow(unused_imports)]
use generated::spire::common::plugin::{
    ConfigureRequest, ConfigureResponse, GetPluginInfoRequest, GetPluginInfoResponse, InitRequest,
    InitResponse,
    plugin_init_server::{PluginInit, PluginInitServer},
    plugin_server::{Plugin, PluginServer},
};
// Use generated config types via fully-qualified paths where needed.
#[allow(unused_imports)]
use generated::spire::plugin::server::upstreamauthority::v1::{
    MintX509caRequest, MintX509caResponse, PublishJwtKeyRequest, PublishJwtKeyResponse,
    upstream_authority_server::{UpstreamAuthority, UpstreamAuthorityServer},
};
#[allow(unused_imports)]
use generated::spire::plugin::types::X509Certificate;
#[allow(unused_imports)]
use generated::spire::service::private::init::v1::{
    DeinitRequest, DeinitResponse, InitRequest as PrivateInitRequest,
    InitResponse as PrivateInitResponse,
    init_server::{Init as PrivateInit, InitServer},
};

#[derive(Clone)]
pub struct UpstreamAuthorityService {
    pub config: Arc<PluginConfig>,
}

#[derive(Clone, Default)]
pub struct PluginService;

#[tonic::async_trait]
impl Plugin for PluginService {
    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let metadata = request.metadata().clone();
        let path = metadata
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());
        let req = request.into_inner();

        tracing::info!(
            service = "Plugin",
            method = "Configure",
            grpc_path = %path,
            configuration_len = req.configuration.len(),
            configuration_preview = %req.configuration,
            global_config_present = req.global_config.is_some(),
            "RPC_ENTER"
        );

        if req.configuration.trim().is_empty() {
            tracing::warn!(
                service = "Plugin",
                method = "Configure",
                grpc_path = %path,
                "RPC_CONFIG_EMPTY"
            );
        }

        let response = ConfigureResponse { error_list: vec![] };

        tracing::info!(
            service = "Plugin",
            method = "Configure",
            grpc_path = %path,
            error_count = response.error_list.len(),
            "RPC_EXIT status=OK"
        );

        Ok(Response::new(response))
    }

    async fn get_plugin_info(
        &self,
        request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());

        tracing::info!(
            service = "Plugin",
            method = "GetPluginInfo",
            grpc_path = %path,
            "RPC_ENTER"
        );

        let response = GetPluginInfoResponse {
            name: "spire-kms-upstream-authority".to_string(),
            category: "UpstreamAuthority".to_string(),
            r#type: "server".to_string(),
            description: "SPIRE upstream authority plugin backed by KMS".to_string(),
            date_created: String::new(),
            location: String::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            author: String::new(),
            company: String::new(),
        };

        tracing::info!(
            service = "Plugin",
            method = "GetPluginInfo",
            grpc_path = %path,
            plugin_name = %response.name,
            plugin_category = %response.category,
            plugin_version = %response.version,
            "RPC_EXIT status=OK"
        );

        Ok(Response::new(response))
    }
}

#[derive(Clone, Default)]
pub struct GoPluginControllerService;

#[tonic::async_trait]
impl GrpcController for GoPluginControllerService {
    async fn shutdown(&self, request: Request<Empty>) -> Result<Response<Empty>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());

        tracing::warn!(
            service = "plugin.GRPCController",
            method = "Shutdown",
            grpc_path = %path,
            "RPC_ENTER shutdown_requested"
        );

        let response = Empty {};
        tracing::warn!(
            service = "plugin.GRPCController",
            method = "Shutdown",
            grpc_path = %path,
            "RPC_EXIT status=OK"
        );
        Ok(Response::new(response))
    }
}

#[derive(Clone)]
pub struct GoPluginStdioService {
    senders: Arc<AsyncMutex<Vec<StdioSender>>>,
}

impl Default for GoPluginStdioService {
    fn default() -> Self {
        Self {
            senders: Arc::new(AsyncMutex::new(Vec::new())),
        }
    }
}

#[tonic::async_trait]
impl GrpcStdio for GoPluginStdioService {
    type StreamStdioStream = tokio_stream::wrappers::ReceiverStream<Result<StdioData, Status>>;

    async fn stream_stdio(
        &self,
        request: Request<()>,
    ) -> Result<Response<Self::StreamStdioStream>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());

        tracing::info!(
            service = "plugin.GRPCStdio",
            method = "StreamStdio",
            grpc_path = %path,
            "RPC_ENTER stdio_stream_requested"
        );

        // Create a channel and store the sender in service state so that it
        // remains alive for the duration of the plugin process. This prevents
        // the host (SPIRE) from receiving EOF on stdio streams.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<StdioData, Status>>(64);
        // Store sender so it isn't dropped at end of this function.
        {
            let mut guard = self.senders.lock().await;
            guard.push(tx.clone());
        }
        tracing::info!(
            service = "plugin.GRPCStdio",
            method = "StreamStdio",
            grpc_path = %path,
            "RPC_EXIT status=OK empty_stream"
        );
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

#[derive(Clone)]
pub struct GoPluginBrokerService {
    senders: Arc<AsyncMutex<Vec<ConnSender>>>,
}

impl Default for GoPluginBrokerService {
    fn default() -> Self {
        Self {
            senders: Arc::new(AsyncMutex::new(Vec::new())),
        }
    }
}

#[tonic::async_trait]
impl GrpcBroker for GoPluginBrokerService {
    type StartStreamStream = tokio_stream::wrappers::ReceiverStream<Result<ConnInfo, Status>>;

    async fn start_stream(
        &self,
        request: Request<tonic::Streaming<ConnInfo>>,
    ) -> Result<Response<Self::StartStreamStream>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());

        tracing::info!(
            service = "plugin.GRPCBroker",
            method = "StartStream",
            grpc_path = %path,
            "RPC_ENTER broker_stream_requested"
        );

        // Create channel and keep sender in service state to ensure the
        // returned stream remains open for the plugin lifetime.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ConnInfo, Status>>(64);
        {
            let mut guard = self.senders.lock().await;
            guard.push(tx.clone());
        }
        tracing::info!(
            service = "plugin.GRPCBroker",
            method = "StartStream",
            grpc_path = %path,
            "RPC_EXIT status=OK empty_stream"
        );
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

#[derive(Clone, Default)]
pub struct PluginInitService;

#[derive(Clone, Default)]
pub struct ConfigService;

#[tonic::async_trait]
impl generated::spire::config::v1::config_server::Config for ConfigService {
    async fn configure(
        &self,
        mut request: Request<generated::spire::config::v1::ConfigureRequest>,
    ) -> Result<Response<generated::spire::config::v1::ConfigureResponse>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<unknown>")
            .to_string();
        let req = request.get_mut();

        tracing::info!(service = "Config", method = "Configure", grpc_path = %path, configuration_len = req.configuration.len(), "RPC_ENTER");

        if req.configuration.trim().is_empty() {
            tracing::info!(
                service = "Config",
                method = "Configure",
                "RPC_CONFIG_EMPTY_TREATED_AS_OK"
            );
            let response = generated::spire::config::v1::ConfigureResponse { error_list: vec![] };
            return Ok(Response::new(response));
        }

        tracing::info!(service = "Config", method = "Configure", configuration_preview = %req.configuration, "RPC_EXIT status=OK");

        let response = generated::spire::config::v1::ConfigureResponse { error_list: vec![] };
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl PluginInit for PluginInitService {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<InitResponse>, Status> {
        let metadata = request.metadata().clone();
        let path = metadata
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());
        let req = request.into_inner();
        tracing::info!(
            service = "PluginInit",
            method = "Init",
            grpc_path = %path,
            host_services = ?req.host_services,
            host_services_count = req.host_services.len(),
            "RPC_ENTER"
        );

        let response = InitResponse {
            plugin_services: vec![
                "spire.config.v1.Config".to_string(),
                "spire.plugin.server.upstreamauthority.v1.UpstreamAuthority".to_string(),
                "grpc.health.v1.Health".to_string(),
            ],
        };

        tracing::info!(
            service = "PluginInit",
            method = "Init",
            grpc_path = %path,
            plugin_services = ?response.plugin_services,
            plugin_service_count = response.plugin_services.len(),
            "RPC_EXIT status=OK"
        );
        Ok(Response::new(response))
    }
}

#[derive(Clone, Default)]
pub struct PrivateInitService;

#[tonic::async_trait]
impl PrivateInit for PrivateInitService {
    async fn init(
        &self,
        request: Request<PrivateInitRequest>,
    ) -> Result<Response<PrivateInitResponse>, Status> {
        let metadata = request.metadata().clone();
        let path = metadata
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());
        let req = request.into_inner();

        tracing::info!(
            service = "spire.service.private.init.v1.Init",
            method = "Init",
            grpc_path = %path,
            host_service_names = ?req.host_service_names,
            host_service_count = req.host_service_names.len(),
            "RPC_ENTER"
        );

        let response = PrivateInitResponse {
            plugin_service_names: vec![
                "spire.config.v1.Config".to_string(),
                "spire.plugin.server.upstreamauthority.v1.UpstreamAuthority".to_string(),
                "grpc.health.v1.Health".to_string(),
            ],
        };

        tracing::info!(
            service = "spire.service.private.init.v1.Init",
            method = "Init",
            grpc_path = %path,
            plugin_service_names = ?response.plugin_service_names,
            plugin_service_count = response.plugin_service_names.len(),
            "RPC_EXIT status=OK"
        );

        Ok(Response::new(response))
    }

    async fn deinit(
        &self,
        request: Request<DeinitRequest>,
    ) -> Result<Response<DeinitResponse>, Status> {
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());

        tracing::info!(
            service = "spire.service.private.init.v1.Init",
            method = "Deinit",
            grpc_path = %path,
            "RPC_ENTER"
        );

        let response = DeinitResponse {};
        tracing::info!(
            service = "spire.service.private.init.v1.Init",
            method = "Deinit",
            grpc_path = %path,
            "RPC_EXIT status=OK"
        );

        Ok(Response::new(response))
    }
}

fn parse_pem_to_der_list(pem_str: &str, label: &str) -> Vec<Vec<u8>> {
    match pem::parse_many(pem_str) {
        Ok(pem_blocks) => {
            let mut der_list = Vec::new();
            for block in pem_blocks {
                der_list.push(block.into_contents());
            }
            der_list
        }
        Err(err) => {
            tracing::error!(error = %err, label = %label, "PEM_PARSE_FAILED");
            Vec::new()
        }
    }
}

fn build_mint_x509ca_response(certs_pem_list: &[String]) -> MintX509caResponse {
    let mut chain = Vec::new();
    for cert_pem in certs_pem_list {
        let der_blocks = parse_pem_to_der_list(cert_pem, "certificate");
        for der in der_blocks {
            chain.push(X509Certificate {
                asn1: der,
                tainted: false,
            });
        }
    }

    // Do not assume last element is root. If a block contains an explicit
    // root certificate, it will be supplied separately by the KMS client
    // and already appended by the caller. Treat the last cert as root only
    // if there is at least one cert and mark it as the upstream root.
    let upstream_x509_roots = if chain.is_empty() {
        Vec::new()
    } else {
        vec![chain.last().cloned().unwrap_or_else(|| X509Certificate {
            asn1: Vec::new(),
            tainted: false,
        })]
    };

    MintX509caResponse {
        x509_ca_chain: chain,
        upstream_x509_roots,
    }
}

#[tonic::async_trait]
impl UpstreamAuthority for UpstreamAuthorityService {
    type MintX509CAAndSubscribeStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<MintX509caResponse, Status>>>;

    async fn mint_x509ca_and_subscribe(
        &self,
        request: Request<MintX509caRequest>,
    ) -> Result<Response<Self::MintX509CAAndSubscribeStream>, Status> {
        let metadata = request.metadata().clone();
        let path = metadata
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());
        let req = request.into_inner();

        // preferred_ttl is in seconds per SPIRE; convert to days for KMS validity
        // If preferred_ttl <= 0, use a safe default of 30 days.
        let validity_days = if req.preferred_ttl > 0 {
            ((req.preferred_ttl as f64) / 86400.0).ceil() as u32
        } else {
            30u32
        };

        tracing::info!(
            service = "UpstreamAuthority",
            method = "MintX509CAAndSubscribe",
            grpc_path = %path,
            csr_len = req.csr.len(),
            preferred_ttl_sec = req.preferred_ttl,
            calculated_validity_days = validity_days,
            request_metadata = ?metadata,
            "RPC_ENTER"
        );

        if req.csr.is_empty() {
            tracing::warn!(
                service = "UpstreamAuthority",
                method = "MintX509CAAndSubscribe",
                grpc_path = %path,
                "RPC_REQUEST_RECEIVED status=INVALID empty CSR"
            );
            return Err(Status::invalid_argument("empty CSR"));
        }

        tracing::info!(
            kms_socket = %self.config.kms_socket_path,
            ca_tag = %self.config.ca_tag,
            csr_len = req.csr.len(),
            preferred_ttl = req.preferred_ttl,
            "RPC_REQUEST_RECEIVED"
        );

        let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", req.csr));
        tracing::info!(
            service = "UpstreamAuthority",
            method = "MintX509CAAndSubscribe",
            grpc_path = %path,
            kms_socket = %self.config.kms_socket_path,
            ca_tag = %self.config.ca_tag,
            csr_pem_len = csr_pem.len(),
            validity_days = validity_days,
            "KMS_SIGN_REQUEST_PREPARED"
        );

        let response = sign_csr_via_kms(
            &self.config.kms_socket_path,
            KmsSignRequest {
                csr_pem,
                ca_tag: self.config.ca_tag.clone(),
                validity_days,
                caller_service: "spire".to_string(),
            },
        )
        .await;

        match &response {
            Ok(resp) => {
                tracing::info!(
                    service = "UpstreamAuthority",
                    method = "MintX509CAAndSubscribe",
                    grpc_path = %path,
                    certificate_pem_len = resp.certificate_pem.len(),
                    root_certificate_pem_present = resp.root_certificate_pem.as_ref().is_some_and(|v| !v.trim().is_empty()),
                    "KMS_SIGN_REQUEST_OK"
                );
            }
            Err(err) => {
                tracing::error!(
                    service = "UpstreamAuthority",
                    method = "MintX509CAAndSubscribe",
                    grpc_path = %path,
                    error = %err,
                    "KMS_SIGN_REQUEST_FAILED"
                );
            }
        }

        let response = response
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

        tracing::info!(
            service = "UpstreamAuthority",
            method = "MintX509CAAndSubscribe",
            grpc_path = %path,
            chain_items_before_conversion = chain.len(),
            "CHAIN_PREPARED"
        );

        if chain.is_empty() {
            tracing::error!(
                service = "UpstreamAuthority",
                method = "MintX509CAAndSubscribe",
                grpc_path = %path,
                "RPC_RETURN status=INTERNAL empty certificate chain"
            );
            return Err(Status::internal(
                "kms-service returned an empty certificate chain",
            ));
        }

        let stream_response = build_mint_x509ca_response(&chain);

        tracing::info!(
            service = "UpstreamAuthority",
            method = "MintX509CAAndSubscribe",
            grpc_path = %path,
            certificates_in_chain = stream_response.x509_ca_chain.len(),
            upstream_roots = stream_response.upstream_x509_roots.len(),
            "RPC_EXIT status=OK"
        );

        Ok(Response::new(tokio_stream::iter(vec![Ok(stream_response)])))
    }

    type PublishJWTKeyAndSubscribeStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<PublishJwtKeyResponse, Status>>>;

    async fn publish_jwt_key_and_subscribe(
        &self,
        _request: Request<PublishJwtKeyRequest>,
    ) -> Result<Response<Self::PublishJWTKeyAndSubscribeStream>, Status> {
        let path = _request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<unknown>");

        tracing::info!(
            service = "UpstreamAuthority",
            method = "PublishJWTKeyAndSubscribe",
            grpc_path = %path,
            request_metadata = ?_request.metadata(),
            "RPC_ENTER"
        );
        tracing::warn!(
            service = "UpstreamAuthority",
            method = "PublishJWTKeyAndSubscribe",
            grpc_path = %path,
            reason = "JWT support intentionally not implemented for this SPIRE plugin",
            "RPC_RETURN_UNIMPLEMENTED"
        );
        Err(Status::unimplemented(
            "JWT key publication is not supported by this SPIRE UpstreamAuthority plugin",
        ))
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

    tracing::info!("PLUGIN_SOCKET_BIND_START path={}", socket_path);
    tracing::info!(
        "Serving SPIRE UpstreamAuthority on plugin socket {}",
        socket_path
    );

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    tracing::info!("HEALTH_REPORTER_CREATED");
    health_reporter
        .set_service_status("", ServingStatus::Serving)
        .await;
    health_reporter
        .set_service_status(
            "spire.plugin.server.upstreamauthority.v1.UpstreamAuthority",
            ServingStatus::Serving,
        )
        .await;

    tracing::info!("HEALTH_SERVICE_REGISTERED");
    tracing::info!("HEALTH_STATUS_SET service=\"\" status=SERVING");
    tracing::info!(
        "HEALTH_STATUS_SET service=spire.plugin.server.upstreamauthority.v1.UpstreamAuthority status=SERVING"
    );

    tracing::debug!(
        service_count = 5,
        "Configured tonic server with UpstreamAuthorityServer and health_service"
    );

    tracing::info!("TONIC_SERVER_START");
    tracing::info!(
        "TONIC_SERVICES: - spire.common.plugin.Plugin - spire.common.plugin.PluginInit - spire.service.private.init.v1.Init - spire.plugin.server.upstreamauthority.v1.UpstreamAuthority - grpc.health.v1.Health"
    );
    tracing::info!(
        socket_path = %socket_path,
        services = 5,
        "TONIC_SERVER_READY"
    );

    let server = tonic::transport::Server::builder()
        .layer(
            tower_http::trace::TraceLayer::new_for_grpc()
                .on_request(|request: &http::Request<_>, _span: &tracing::Span| {
                    tracing::info!(grpc_path = %request.uri().path(), "gRPC_REQUEST_RECEIVED");
                })
                .on_response(|response: &http::Response<_>, _latency: std::time::Duration, _span: &tracing::Span| {
                    tracing::info!(status_code = %response.status(), grpc_path = %response.status(), "gRPC_RESPONSE_SENT");
                }),
        )
        .add_service(PluginServer::new(PluginService::default()))
        .add_service(
            // Config service required by newer SPIRE servers to deliver plugin configuration
            // Implemented below as ConfigService
            generated::spire::config::v1::config_server::ConfigServer::new(ConfigService::default()),
        )
        .add_service(PluginInitServer::new(PluginInitService::default()))
        .add_service(InitServer::new(PrivateInitService::default()))
        .add_service(GrpcControllerServer::new(GoPluginControllerService::default()))
        .add_service(GrpcStdioServer::new(GoPluginStdioService::default()))
        .add_service(GrpcBrokerServer::new(GoPluginBrokerService::default()))
        .add_service(UpstreamAuthorityServer::new(service))
        .add_service(health_service);

    tracing::info!("TONIC_SERVER_REGISTERED_ALL_SERVICES");

    // Register Config service for SPIRE plugin configuration compatibility.
    tracing::info!("REGISTERING_CONFIG_SERVICE");

    tokio::select! {
        result = server.serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)) => {
            tracing::info!(result = ?result, "TONIC_SERVER_SERVE_WITH_INCOMING_RETURNED");
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
    tracing::info!(
        "PLUGIN_SOCKET_PREPARE_START path={}",
        config.spire_plugin_socket_path
    );
    prepare_plugin_socket_path(&config.spire_plugin_socket_path).await?;
    tracing::info!(
        "PLUGIN_SOCKET_PREPARE_OK path={}",
        config.spire_plugin_socket_path
    );

    tracing::info!(
        "PLUGIN_SOCKET_BIND_START path={}",
        config.spire_plugin_socket_path
    );

    let listener = tokio::net::UnixListener::bind(&config.spire_plugin_socket_path)?;
    tracing::info!(
        "PLUGIN_SOCKET_BIND_OK path={}",
        config.spire_plugin_socket_path
    );

    std::fs::set_permissions(
        &config.spire_plugin_socket_path,
        std::fs::Permissions::from_mode(0o660),
    )?;
    tracing::info!(
        "PLUGIN_SOCKET_PERMISSIONS_OK mode=0660 path={}",
        config.spire_plugin_socket_path
    );

    tracing::info!("HANDSHAKE_START path={}", config.spire_plugin_socket_path);
    if let Err(e) = crate::emit_go_plugin_handshake(&config.spire_plugin_socket_path) {
        tracing::error!(error = %e, "HANDSHAKE_WRITE_FAILED");
        return Err(e);
    }
    tracing::info!("HANDSHAKE_OK path={}", config.spire_plugin_socket_path);

    tracing::info!(
        "PLUGIN_SOCKET_READY_FOR_SPIRE path={}",
        config.spire_plugin_socket_path
    );

    let result = serve_with_listener(config, listener).await;
    tracing::info!(
        server_result = ?result,
        "PLUGIN_SERVE_WITH_LISTENER_EXIT"
    );
    result
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub async fn serve(_config: PluginConfig) -> anyhow::Result<()> {
    anyhow::bail!(
        "SPIRE upstream authority Unix Domain Socket support is only available on Unix-like systems; this host is {}",
        std::env::consts::OS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plugin_configure_returns_success() {
        let response = PluginService
            .configure(Request::new(ConfigureRequest {
                configuration: "".to_string(),
                global_config: None,
            }))
            .await
            .expect("plugin configure should succeed");

        assert!(response.into_inner().error_list.is_empty());
    }

    #[test]
    fn builds_first_stream_response_from_signed_certificate() {
        let root_cert = r#"-----BEGIN CERTIFICATE-----
MIIC3zCCAcegAwIBAgIUEVKTaQkekN/ztlAvCHN+v851/1owDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDkyNzE1MTY0NFoXDTI3
MDkyNzE1MTY0NFowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHGbzBbDp+b70JcuKTfGNrMrTAWQuwDO0vfO
bTwER/oSrL1YTkoA/aO6r8imVubdF0foUXuvt9QFhwkSKQIZzkkVLOQY5jZEQiQm
GH0JM4y33/NSuX+Is6dP4tZBpLlGw3eaIOZxLMHD4md8i1897MITDAUnOs1VEyHt
FtpekIZUZ0+nb8RLactKNn0NRrjGDhIx5enL/hFGI8zaEgA+OyYlb153hhi/2suo
Ds0cm7G1S8K1nGbx15hoNqthQtls8ouX2CMNx5ljbHIExbIkebWckoepAz2VskCA
WjKUnhWBO+EnaslHQImrMVtlfGS1xyAPzW8yRrOdg/WBNwQMFwIDAQABoyMwITAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOC
AQEANB00aX03BZcY4LkzEqmQxixZiUuWHoYMBnk/5qxlhRgTzPi0A8kW2K3lp7VT
h048ZZFGG5E3JfsY2wPpGXcULBpHlOw37sz9kCzFENBn92yJcWtaQLfw4AXGiM5u
iv4EAq5//dTfX8uVhiF4QwWg3V6OG41cmW9gAhsArRiuQfcTmGpeP+pC/8xJVhjG
kjpL+oMSToZEi7OjcDzHflLWs1NwNtJosguKMzKzawIucS+uh3Y/CcJpg7v0nj86
OLqJgqLRWhIwXxb+/FgcgVjyb+rgier8NFi1H8TURsigZvp56G4xXjlS4zayQM2E
l1QoCI0IU38B1DcQpjJjmbH+Sw==
-----END CERTIFICATE-----"#;
        let leaf_cert = r#"-----BEGIN CERTIFICATE-----
MIICtzCCAZ+gAwIBAgIUZZ49J6BXbQmTAcVROrtch/fukTcwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDkyNzE1MTY0NFoXDTI3
MDkyNzE1MTY0NFowFDESMBAGA1UEAwwJVGVzdCBMZWFmMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAsISX9h9vZrpPoXYKoM73Q5S1+XLp9YsG6rWSijVt
sy59ckAtvh0+68edRac5FhJZ8U4Z7MlEHedGWI1u1V0FEMmjaeV2vqWaZt/K++By
MDl4pfT1wi3V/oAvRLDcvWt6ZifbpErPJwE47ZwzdGUmREzqEe0FEa0biUM2ADqd
FNntDaxBRlsEfk+/zJvxlqpXs7AvBp7JaLbIRBNRvbMoBKFfoUXstXGYWDwkf4WL
UPSuTKbV5VMs88t1kOG0PZhEaoysIBnVargd0nlUxp01FwVPZ4FE4geZ2U8Ej2WO
M93Bjn2Cc8ZskmdfkdCEbiTTiZq1EmHKo8fc3fcSS0p9BQIDAQABMA0GCSqGSIb3
DQEBCwUAA4IBAQCRVaw/tpCXLlhwqhvm6tW8lp86AeDvJoNpfPbolxpKVvOk5Cdl
rX4gcq105bp4Oq4Dmm6ImRsWsdtAwYpp3DGmXyTuHgprxBlMBjxElSU2VfcRfUZ6
dMsVOLowlQO503ljgGg79sDuYbidD644FmzmPspoHQgy4Q9hS/1UdeieUS0I3S64
7gdqZ1TQgRuPdj5Dh2Q0xo3UtjEaoAkXYta229PL6Rl+nU5ekS490HEoJoXY+b+7
2K7NDsZnX3nXpPOPI+0hXutw0Pz7DEH/Oy/W9UYplPBS5C07Ue/SWUoMzKk+nfTE
rTcwViK3d+ALfhamH6lbyzLnbMlLxVFEPH07
-----END CERTIFICATE-----"#;

        let response = build_mint_x509ca_response(&[leaf_cert.to_string(), root_cert.to_string()]);

        assert_eq!(response.x509_ca_chain.len(), 2);
        assert_eq!(response.upstream_x509_roots.len(), 1);
        assert!(!response.x509_ca_chain[0].asn1.is_empty());
    }

    #[test]
    fn rejects_empty_certificate_chain() {
        let response = build_mint_x509ca_response(&[]);
        assert!(response.x509_ca_chain.is_empty());
        assert!(response.upstream_x509_roots.is_empty());
    }
}
