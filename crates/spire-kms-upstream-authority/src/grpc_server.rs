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
    pub mod spire {
        pub mod common {
            pub mod plugin {
                tonic::include_proto!("spire.common.plugin");
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
    }
}

use generated::spire::common::plugin::{
    plugin_init_server::{PluginInit, PluginInitServer},
    InitRequest, InitResponse,
};
use generated::spire::plugin::server::upstreamauthority::v1::{
    MintX509caRequest, MintX509caResponse, PublishJwtKeyRequest, PublishJwtKeyResponse,
    upstream_authority_server::{UpstreamAuthority, UpstreamAuthorityServer},
};
use generated::spire::plugin::types::X509Certificate;

#[derive(Clone)]
pub struct UpstreamAuthorityService {
    pub config: Arc<PluginConfig>,
}

#[derive(Clone, Default)]
pub struct PluginInitService;

#[tonic::async_trait]
impl PluginInit for PluginInitService {
    async fn init(
        &self,
        request: Request<InitRequest>,
    ) -> Result<Response<InitResponse>, Status> {
        let path = request
            .metadata()
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
            "RPC_ENTER"
        );
        tracing::info!(
            service = "PluginInit",
            method = "Init",
            grpc_path = %path,
            "RPC_EXIT status=OK"
        );
        Ok(Response::new(InitResponse {
            plugin_services: vec![
                "spire.plugin.server.upstreamauthority.v1.UpstreamAuthority".to_string(),
                "grpc.health.v1.Health".to_string(),
            ],
        }))
    }
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>, Status> {
    pem::parse(pem)
        .map(|block| block.contents().to_vec())
        .map_err(|err| Status::internal(format!("invalid {label} PEM: {err}")))
}

fn build_mint_x509ca_response(certs: &[String]) -> MintX509caResponse {
    let mut chain = Vec::with_capacity(certs.len());
    for cert_pem in certs {
        let Ok(der) = pem_to_der(cert_pem, "certificate") else {
            continue;
        };
        chain.push(X509Certificate {
            asn1: der,
            tainted: false,
        });
    }

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
        let path = request
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_string());
        let req = request.into_inner();

        tracing::info!(
            service = "UpstreamAuthority",
            method = "MintX509CAAndSubscribe",
            grpc_path = %path,
            csr_len = req.csr.len(),
            preferred_ttl = req.preferred_ttl,
            "RPC_ENTER"
        );

        if req.csr.is_empty() {
            tracing::warn!(
                service = "UpstreamAuthority",
                method = "MintX509CAAndSubscribe",
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
        let response = sign_csr_via_kms(
            &self.config.kms_socket_path,
            KmsSignRequest {
                csr_pem,
                ca_tag: self.config.ca_tag.clone(),
                validity_days: req.preferred_ttl.max(1) as u32,
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

        let stream_response = build_mint_x509ca_response(&chain);

        tracing::info!(
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
            "RPC_ENTER"
        );
        tracing::warn!(
            service = "UpstreamAuthority",
            method = "PublishJWTKeyAndSubscribe",
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

    tracing::info!(
        "PLUGIN_SOCKET_BIND_START path={}",
        socket_path
    );
    tracing::info!(
        "Serving SPIRE UpstreamAuthority on plugin socket {}",
        socket_path
    );

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
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
        service_count = 2,
        "Configured tonic server with UpstreamAuthorityServer and health_service"
    );

    tracing::info!("TONIC_SERVER_START");
    tracing::info!("TONIC_SERVICES: - spire.plugin.server.upstreamauthority.v1.UpstreamAuthority - grpc.health.v1.Health - spire.common.plugin.PluginInit");

    let server = tonic::transport::Server::builder()
        .add_service(UpstreamAuthorityServer::new(service))
        .add_service(PluginInitServer::new(PluginInitService::default()))
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

    tracing::info!(
        "PLUGIN_SOCKET_BIND_START path={}"
        , config.spire_plugin_socket_path
    );

    let listener = tokio::net::UnixListener::bind(&config.spire_plugin_socket_path)?;
    tracing::info!(
        "PLUGIN_SOCKET_BIND_OK path={}"
        , config.spire_plugin_socket_path
    );

    std::fs::set_permissions(
        &config.spire_plugin_socket_path,
        std::fs::Permissions::from_mode(0o660),
    )?;
    tracing::info!(
        "PLUGIN_SOCKET_PERMISSIONS_OK mode=0660 path={}"
        , config.spire_plugin_socket_path
    );

    tracing::info!(
        "HANDSHAKE_START path={}"
        , config.spire_plugin_socket_path
    );
    crate::emit_go_plugin_handshake(&config.spire_plugin_socket_path)?;
    tracing::info!(
        "HANDSHAKE_OK path={}"
        , config.spire_plugin_socket_path
    );

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(response.x509_ca_chain[0].asn1.len() > 0);
    }

    #[test]
    fn rejects_empty_certificate_chain() {
        let response = build_mint_x509ca_response(&[]);
        assert!(response.x509_ca_chain.is_empty());
        assert!(response.upstream_x509_roots.is_empty());
    }
}
