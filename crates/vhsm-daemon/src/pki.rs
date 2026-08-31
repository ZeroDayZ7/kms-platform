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

    // serialize cert and private key (DER)
    let cert_der = cert.serialize_der().map_err(|e| e.to_string())?;
    let key_der = cert.get_key_pair().serialize_der();

    // store private key in Zeroizing wrapper
    state.pki.ca_private_key = Some(Zeroizing::new(key_der));
    state.pki.ca_certificate = Some(cert_der.clone());

    info!("[PKI] Root CA wygenerowany");

    Ok(cert_der)
}

/// Placeholder: full PKCS#10 CSR signing will be implemented next.
pub fn sign_csr(_state: &VhsmState, _csr_der: &[u8], _is_server: bool) -> Result<Vec<u8>, String> {
    info!("[PKI] CSR signing requested but not implemented yet");
    Err("SignCertificate (CSR) not implemented yet".to_string())
}
