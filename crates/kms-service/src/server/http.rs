use anyhow::Context;
use axum::{Router, body::Body as AxumBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{signal, time::Duration};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::{error, info, warn};
use hyper_util::service::TowerToHyperService;
use crate::config::Settings;
use crate::domain::auth::{Principal, WorkloadIdentityConfig};
use crate::infrastructure::identity::SpiffeX509IdentityProvider;

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
    serve_mtls_with_config(router, addr, tls_config, shutdown_timeout, shutdown_token).await
}

pub async fn serve_mtls_with_config(
    router: Router,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
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

                tokio::spawn(async move {
                    let acceptor = TlsAcceptor::from(tls_config);
                    let stream = acceptor
                        .accept(stream)
                        .await
                        .with_context(|| "mTLS handshake failed")?;

                    let principal = peer_principal_from_tls(&stream)?;
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

fn peer_principal_from_tls(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<Principal> {
    let (_, session) = stream.get_ref();
    let cert = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("mTLS peer did not present a client certificate")?;

    let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig {
        enabled: true,
        trust_domain: Some("example.org".to_string()),
        workload_id: None,
        spire_agent_socket_path: None,
        tls_identity: Default::default(),
        rotation_interval_secs: 300,
    });

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
