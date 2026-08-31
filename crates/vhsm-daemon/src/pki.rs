// crates/vhsm-daemon/src/pki.rs
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use tracing::info;
use zeroize::Zeroizing;

use crate::state::VhsmState;

/// Generate a new Root CA and store private key securely in memory inside `state`.
pub fn generate_root_ca(state: &mut VhsmState, common_name: &str) -> Result<Vec<u8>, String> {
    if state.pki.ca_certificate.is_some() || state.pki.ca_private_key.is_some() {
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

    // store private key in Zeroizing wrapper (DER), certificate PEM for distribution
    state.pki.ca_private_key = Some(Zeroizing::new(key_der));
    state.pki.ca_certificate = Some(cert_pem.clone().into_bytes());
    state.pki.ca_subject_cn = Some(common_name.to_string());

    info!("[PKI] Root CA wygenerowany");

    Ok(cert_pem.into_bytes())
}

/// Placeholder: full PKCS#10 CSR signing will be implemented next.
pub fn sign_csr(_state: &VhsmState, _csr_der: &[u8], _is_server: bool) -> Result<Vec<u8>, String> {
    info!("[PKI] CSR signing requested but not implemented yet");
    Err("SignCertificate (CSR) not implemented yet".to_string())
}

/// Issue a certificate signed by the Root CA. Returns (cert_pem, key_pem).
pub fn issue_certificate_for(
    state: &VhsmState,
    subject_cn: &str,
    san_dns: Vec<String>,
    san_ips: Vec<std::net::IpAddr>,
    is_server: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Ensure CA exists
    let ca_key = state
        .pki
        .ca_private_key
        .as_ref()
        .ok_or_else(|| "Root CA not initialized".to_string())?;
    let ca_cert_der = state
        .pki
        .ca_certificate
        .as_ref()
        .ok_or_else(|| "Root CA certificate missing".to_string())?;

    let ca_subject = state
        .pki
        .ca_subject_cn
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "KMS Root CA".to_string());

    // Build CA signer Certificate object
    let mut ca_params = CertificateParams::new(vec![ca_subject]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    ca_params.key_pair = Some(KeyPair::from_der(&*ca_key).map_err(|e| e.to_string())?);
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
pub fn bootstrap_pki(
    state: &mut VhsmState,
    admin_cn: &str,
    server_domain: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    info!("[PKI] Bootstrap PKI started");

    // generate root CA
    let ca_pem = generate_root_ca(state, "KMS Root CA")?;
    // issue server cert: SANs localhost and 127.0.0.1 and server_domain
    let san_dns = vec!["localhost".to_string(), server_domain.to_string()];
    let san_ips = vec!["127.0.0.1".parse().unwrap()];
    let (server_cert_pem, server_key_pem) = issue_certificate_for(state, server_domain, san_dns, san_ips, true)?;

    // issue admin client cert
    let (admin_cert_pem, admin_key_pem) = issue_certificate_for(state, admin_cn, vec![], vec![], false)?;

    info!("[PKI] Bootstrap PKI completed");

    Ok((ca_pem, server_cert_pem, server_key_pem, admin_cert_pem, admin_key_pem))
}
