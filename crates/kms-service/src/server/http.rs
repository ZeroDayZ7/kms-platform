use crate::config::Settings;
use crate::domain::auth::{Principal, WorkloadIdentityConfig};
use crate::infrastructure::identity::SpiffeX509IdentityProvider;
use anyhow::Context;
use axum::{Router, body::Body as AxumBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{signal, time::Duration};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::{error, info, warn};

pub async fn serve(
    router: Router,
    addr: SocketAddr,
    shutdown_timeout: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    info!("🚀 Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    server
        .with_graceful_shutdown(shutdown_signal(shutdown_timeout, shutdown_token.clone()))
        .await
        .context("Axum server error")?;

    Ok(())
}

pub async fn serve_mtls(
    router: Router,
    addr: SocketAddr,
    settings: Arc<Settings>,
    shutdown_timeout: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    let tls_config = build_mtls_server_config(&settings)?;
    let provider = spiffe_provider_from_settings(&settings);
    serve_mtls_with_config(
        router,
        addr,
        tls_config,
        provider,
        shutdown_timeout,
        shutdown_token,
    )
    .await
}

pub async fn serve_mtls_with_config(
    router: Router,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    provider: SpiffeX509IdentityProvider,
    shutdown_timeout: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    info!("🚀 mTLS listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    let shutdown = shutdown_signal(shutdown_timeout, shutdown_token.clone());
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("failed to accept mTLS client connection")?;
                let tls_config = tls_config.clone();
                let router = router.clone();
                let provider = provider.clone();

                tokio::spawn(async move {
                    let acceptor = TlsAcceptor::from(tls_config);
                    let stream = acceptor
                        .accept(stream)
                        .await
                        .with_context(|| "mTLS handshake failed")?;

                    let principal = peer_principal_from_tls(&provider, &stream)?;
                    let router = router.clone();
                    let service = tower::service_fn(move |mut req: http::Request<Incoming>| {
                        let router = router.clone();
                        let principal = principal.clone();
                        async move {
                            req.extensions_mut().insert(principal);
                            let req = req.map(AxumBody::new);
                            router.clone().oneshot(req).await.map_err(|err| {
                                std::io::Error::new(std::io::ErrorKind::Other, err)
                            })
                        }
                    });
                    let hyper_service = TowerToHyperService::new(service);

                    let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), hyper_service);
                    if let Err(err) = connection.await {
                        error!(error = %err, "mTLS connection closed with error");
                    }
                    Ok::<(), anyhow::Error>(())
                });
            }
        }
    }

    Ok(())
}

fn build_mtls_server_config(settings: &Settings) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_path = settings
        .auth
        .spiffe
        .tls_cert_path
        .as_deref()
        .context("SPIFFE TLS certificate path is missing")?;
    let key_path = settings
        .auth
        .spiffe
        .tls_key_path
        .as_deref()
        .context("SPIFFE TLS private key path is missing")?;
    let bundle_path = settings
        .auth
        .spiffe
        .trust_bundle_path
        .as_deref()
        .context("SPIFFE trust bundle path is missing")?;

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read server certificate from {}", cert_path))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("failed to read server private key from {}", key_path))?;
    let bundle_pem = std::fs::read(bundle_path)
        .with_context(|| format!("failed to read trust bundle from {}", bundle_path))?;

    let cert_chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid server certificate PEM from {}", cert_path))?;
    let private_key = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("invalid private key PEM from {}", key_path))?;

    let roots = RootCertStore::empty();
    let mut root_store = roots;
    let client_anchors = CertificateDer::pem_slice_iter(&bundle_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid client trust bundle PEM from {}", bundle_path))?;
    root_store.add_parsable_certificates(client_anchors);

    let verifier = WebPkiClientVerifier::builder(root_store.into())
        .build()
        .context("invalid mTLS client certificate verifier configuration")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, private_key)
        .context("failed to configure rustls server certificate and mTLS verifier")?;

    Ok(Arc::new(config))
}

fn spiffe_provider_from_settings(settings: &Settings) -> SpiffeX509IdentityProvider {
    SpiffeX509IdentityProvider::new(WorkloadIdentityConfig {
        enabled: true,
        trust_domain: settings.auth.spiffe.trust_domain.clone(),
        workload_id: settings.auth.spiffe.workload_id.clone(),
        spire_agent_socket_path: settings.auth.spiffe.spire_agent_socket_path.clone(),
        tls_identity: Default::default(),
        rotation_interval_secs: settings.auth.spiffe.rotation_interval_secs.unwrap_or(300),
        identity_mode: match settings.auth.spiffe.identity_mode {
            crate::config::SpiffeIdentityMode::Authoritative => {
                crate::domain::auth::SpiffeIdentityMode::Authoritative
            }
            crate::config::SpiffeIdentityMode::FileFallback => {
                crate::domain::auth::SpiffeIdentityMode::FileFallback
            }
        },
    })
}

fn peer_principal_from_tls(
    provider: &SpiffeX509IdentityProvider,
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<Principal> {
    let (_, session) = stream.get_ref();
    let cert = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("mTLS peer did not present a client certificate")?;

    provider
        .validate_spiffe_identity(cert.as_ref())
        .with_context(|| {
            "mTLS client certificate is not a valid SPIFFE identity for this service".to_string()
        })
}

async fn shutdown_signal(timeout: u64, shutdown_token: CancellationToken) {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            warn!(error = %error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut terminate_signal) => {
                terminate_signal.recv().await;
            }
            Err(error) => {
                warn!(error = %error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Ctrl+C received"),
        _ = terminate => info!("🛑 SIGTERM received"),
    }

    shutdown_token.cancel();
    info!("⏳ Graceful shutdown started ({}s)", timeout);

    tokio::time::sleep(Duration::from_secs(timeout)).await;

    warn!("⚠️ Shutdown timeout reached");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use http::StatusCode;
    use reqwest::{Certificate, Client, Identity};
    use rustls::crypto::aws_lc_rs::default_provider;
    use std::process::Command;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    fn install_rustls_crypto() {
        let _ = default_provider().install_default();
    }

    fn generate_ca(dir: &TempDir, name: &str) -> anyhow::Result<(String, String)> {
        let ca_key = dir.path().join(format!("{name}-ca.key"));
        let ca_crt = dir.path().join(format!("{name}-ca.crt"));

        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_crt.to_str().unwrap(),
                "-days",
                "365",
                "-subj",
                "/CN=KMS Test Root CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("openssl failed to generate CA certificate");
        }

        Ok((
            std::fs::read_to_string(&ca_crt)?,
            std::fs::read_to_string(&ca_key)?,
        ))
    }

    fn generate_leaf_signed_by_ca(
        dir: &TempDir,
        name: &str,
        uri: &str,
        ca_pem: &str,
        ca_key_pem: &str,
    ) -> anyhow::Result<(String, String)> {
        let ca_key = dir.path().join(format!("{name}-ca.key"));
        let ca_crt = dir.path().join(format!("{name}-ca.crt"));
        let leaf_key = dir.path().join(format!("{name}.key"));
        let leaf_csr = dir.path().join(format!("{name}.csr"));
        let leaf_crt = dir.path().join(format!("{name}.crt"));
        let ext_file = dir.path().join(format!("{name}.ext"));

        std::fs::write(&ca_crt, ca_pem)?;
        std::fs::write(&ca_key, ca_key_pem)?;
        std::fs::write(
            &ext_file,
            format!(
                "subjectAltName=URI:{uri},DNS:localhost\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\n",
            ),
        )?;

        let status = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                leaf_key.to_str().unwrap(),
                "-out",
                leaf_csr.to_str().unwrap(),
                "-subj",
                &format!("/CN={name}"),
                "-addext",
                &format!("subjectAltName=URI:{uri},DNS:localhost"),
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("openssl failed to create leaf CSR");
        }

        let status = Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                leaf_csr.to_str().unwrap(),
                "-CA",
                ca_crt.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                leaf_crt.to_str().unwrap(),
                "-days",
                "30",
                "-sha256",
                "-extfile",
                ext_file.to_str().unwrap(),
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("openssl failed to sign leaf certificate");
        }

        Ok((
            std::fs::read_to_string(&leaf_crt)?,
            std::fs::read_to_string(&leaf_key)?,
        ))
    }

    fn build_server_config(
        ca_pem: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<ServerConfig> {
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())?;
        let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
        let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes())?;

        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(vec![ca_der]);
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .context("failed to build client verifier")?;

        Ok(ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert_der], key_der)
            .context("failed to build mTLS server config")?)
    }

    async fn wait_for_server(addr: SocketAddr) {
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn make_client_with_identity(
        root_pem: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<Client> {
        Ok(Client::builder()
            .use_rustls_tls()
            .add_root_certificate(Certificate::from_pem(root_pem.as_bytes())?)
            .identity(Identity::from_pem(
                format!("{cert_pem}{key_pem}").as_bytes(),
            )?)
            .build()?)
    }

    #[tokio::test]
    async fn accepts_valid_mtls_client_with_spiffe_identity() -> anyhow::Result<()> {
        install_rustls_crypto();
        let dir = tempfile::tempdir()?;
        let valid_uri = "spiffe://example.org/ns/default/workload/kms";
        let (ca_pem, ca_key_pem) = generate_ca(&dir, "kms-root")?;
        let (client_cert_pem, client_key_pem) =
            generate_leaf_signed_by_ca(&dir, "client", valid_uri, &ca_pem, &ca_key_pem)?;
        let (server_cert_pem, server_key_pem) =
            generate_leaf_signed_by_ca(&dir, "server", valid_uri, &ca_pem, &ca_key_pem)?;

        let app = Router::new().route("/health", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        drop(listener);

        let server_config = Arc::new(build_server_config(
            &ca_pem,
            &server_cert_pem,
            &server_key_pem,
        )?);
        let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig {
            enabled: true,
            trust_domain: Some("example.org".to_string()),
            workload_id: Some("/ns/default/workload/kms".to_string()),
            ..Default::default()
        });
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            let _ =
                serve_mtls_with_config(app, addr, server_config, provider, 1, server_cancel).await;
        });

        wait_for_server(addr).await;

        let client = make_client_with_identity(&ca_pem, &client_cert_pem, &client_key_pem)?;
        let response = client
            .get(format!("https://localhost:{}/health", addr.port()))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await?;
        assert_eq!(body, "ok");

        cancel.cancel();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_client_without_certificate() -> anyhow::Result<()> {
        install_rustls_crypto();
        let dir = tempfile::tempdir()?;
        let valid_uri = "spiffe://example.org/ns/default/workload/kms";
        let (ca_pem, ca_key_pem) = generate_ca(&dir, "kms-root")?;
        let (server_cert_pem, server_key_pem) =
            generate_leaf_signed_by_ca(&dir, "server", valid_uri, &ca_pem, &ca_key_pem)?;

        let app = Router::new().route("/health", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        drop(listener);

        let server_config = Arc::new(build_server_config(
            &ca_pem,
            &server_cert_pem,
            &server_key_pem,
        )?);
        let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig {
            enabled: true,
            trust_domain: Some("example.org".to_string()),
            workload_id: Some("/ns/default/workload/kms".to_string()),
            ..Default::default()
        });
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            let _ =
                serve_mtls_with_config(app, addr, server_config, provider, 1, server_cancel).await;
        });

        wait_for_server(addr).await;

        let client = Client::builder()
            .use_rustls_tls()
            .add_root_certificate(Certificate::from_pem(ca_pem.as_bytes())?)
            .build()?;
        let result = client.get(format!("https://{addr}/health")).send().await;
        assert!(result.is_err());

        cancel.cancel();
        let _ = server.await;
        Ok(())
    }
}
