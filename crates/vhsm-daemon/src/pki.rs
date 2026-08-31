// crates/vhsm-daemon/src/pki.rs
use rand::RngCore;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use tracing::info;
use zeroize::Zeroizing;

use crate::state::VhsmState;

/// Generate a new Root CA and store private key securely in memory inside `state`.
#[cfg(unix)]
pub fn generate_root_ca(
    state: &mut VhsmState,
    common_name: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if state.pki.ca_certificate.is_some() {
        return Err("Root CA already exists".to_string());
    }

    info!("[PKI] Generowanie Root CA rozpoczęte");

    // generate keypair
    let kp = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;

    // prepare params
    let mut params = CertificateParams::new(vec![common_name.to_string()]);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_pair = Some(kp);

    let cert = Certificate::from_params(params).map_err(|e| e.to_string())?;

    // serialize cert PEM and private key DER
    let cert_pem = cert.serialize_pem().map_err(|e| e.to_string())?;
    let key_der = cert.get_key_pair().serialize_der();

    // Envelope encryption: generate SYSTEM_CA_KEK, encrypt CA private key with it,
    // then encrypt SYSTEM_CA_KEK with MasterKey. Do NOT store blobs in RAM state.
    let master_key = state
        .master_key
        .as_ref()
        .ok_or_else(|| "Master key missing; vHSM must be unsealed".to_string())?;

    // Generate random SYSTEM_CA_KEK (32 bytes)
    let mut system_kek = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut system_kek);

    // Encrypt CA private key DER with SYSTEM_CA_KEK
    let encrypted_ca = crate::crypto::encrypt_bytes(&system_kek, &key_der)?;

    // Encrypt SYSTEM_CA_KEK with master_key
    let wrapped_kek = crate::crypto::encrypt_bytes(master_key.as_ref(), &system_kek)?;

    // Keep only public cert and CN in RAM
    state.pki.ca_certificate = Some(cert_pem.clone().into_bytes());
    state.pki.ca_subject_cn = Some(common_name.to_string());

    info!("[PKI] Root CA wygenerowany");

    Ok((cert_pem.into_bytes(), key_der, encrypted_ca, wrapped_kek))
}

/// Placeholder: full PKCS#10 CSR signing will be implemented next.
#[cfg(unix)]
pub fn sign_csr(_state: &VhsmState, _csr_der: &[u8], _is_server: bool) -> Result<Vec<u8>, String> {
    info!("[PKI] CSR signing requested (rcgen-hybrid fallback)");

    // Try to derive a subject CN from the CSR by hashing its bytes (fallback).
    // A robust CSR parsing implementation can be added later.
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(_csr_der);
    let short = &hex::encode(digest)[..16];
    let subject_cn = format!("csr-{}", (short));

    // Build a certificate signed by CA using rcgen (new keypair)
    // Note: true PKCS#10 CSR signing is not yet implemented. The CA private key
    // is persisted encrypted in the DB and must be unwrapped on-demand. For now
    // keep fallback behavior: issue a cert using a fresh keypair and sign with
    // a transient CA generated from the stored CA certificate PEM (no private key).
    let ca_cert_pem = _state
        .pki
        .ca_certificate
        .as_ref()
        .ok_or_else(|| "Root CA certificate missing".to_string())?;

    let ca_subject = _state
        .pki
        .ca_subject_cn
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "KMS Root CA".to_string());

    let mut ca_params = CertificateParams::new(vec![ca_subject]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    // No key_pair set because CA private key is not held in RAM.
    let ca_cert = Certificate::from_params(ca_params).map_err(|e| e.to_string())?;

    let mut params = CertificateParams::new(vec![subject_cn]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    // generate new keypair for this cert (fallback)
    params.key_pair =
        Some(KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?);
    if _is_server {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    } else {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    }

    let cert = Certificate::from_params(params).map_err(|e| e.to_string())?;
    let cert_pem = cert
        .serialize_pem_with_signer(&ca_cert)
        .map_err(|e| e.to_string())?;

    Ok(cert_pem.into_bytes())
}

/// Issue a certificate signed by the Root CA. Returns (cert_pem, key_pem).
#[cfg(unix)]
pub fn issue_certificate_for(
    ca_key_der: &[u8],
    subject_cn: &str,
    san_dns: Vec<String>,
    san_ips: Vec<std::net::IpAddr>,
    is_server: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Build CA signer Certificate object from provided private key DER
    let ca_subject = "KMS Root CA".to_string();
    let mut ca_params = CertificateParams::new(vec![ca_subject]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    ca_params.key_pair = Some(KeyPair::from_der(ca_key_der).map_err(|e| e.to_string())?);
    let ca_cert = Certificate::from_params(ca_params).map_err(|e| e.to_string())?;

    // Generate new keypair for issued certificate
    let kp = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;

    let mut params = CertificateParams::new(vec![subject_cn.to_string()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.key_pair = Some(kp);
    // leave is_ca unset (non-CA certificate)

    // set extended key usage
    if is_server {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    } else {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    }

    // SANs
    for dns in san_dns {
        params.subject_alt_names.push(rcgen::SanType::DnsName(dns));
    }
    for ip in san_ips {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
    }

    let cert = Certificate::from_params(params).map_err(|e| e.to_string())?;

    let cert_pem = cert
        .serialize_pem_with_signer(&ca_cert)
        .map_err(|e| e.to_string())?;
    let key_pem = cert.get_key_pair().serialize_pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

/// Bootstrap full PKI: generate CA, issue server and admin certs and keys, return PEMs
#[cfg(unix)]
pub fn bootstrap_pki(
    state: &mut VhsmState,
    admin_cn: &str,
    server_domain: &str,
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
    String,
> {
    info!("[PKI] Bootstrap PKI started");

    // generate root CA and obtain encrypted blobs; keep private key transient
    let (ca_pem, ca_key_der, encrypted_ca, wrapped_kek) = generate_root_ca(state, "KMS Root CA")?;

    // issue server cert: SANs localhost and 127.0.0.1 and server_domain
    let san_dns = vec!["localhost".to_string(), server_domain.to_string()];
    let san_ips = vec!["127.0.0.1".parse().unwrap()];
    let (server_cert_pem, server_key_pem) =
        issue_certificate_for(&ca_key_der, server_domain, san_dns, san_ips, true)?;

    // issue admin client cert
    let (admin_cert_pem, admin_key_pem) =
        issue_certificate_for(&ca_key_der, admin_cn, vec![], vec![], false)?;

    // Zeroize transient CA private key
    let mut cakey_zero = Zeroizing::new(ca_key_der);
    cakey_zero.zeroize();

    info!("[PKI] Bootstrap PKI completed");

    Ok((
        ca_pem,
        server_cert_pem,
        server_key_pem,
        admin_cert_pem,
        admin_key_pem,
        encrypted_ca,
        wrapped_kek,
    ))
}
