use rcgen::{Certificate, CertificateParams, IsCa, BasicConstraints, KeyPair, PKCS_ECDSA_P256_SHA256};
use zeroize::Zeroizing;
use tracing::info;

use crate::state::VhsmState;

/// Generate a new Root CA and store private key securely in memory inside `state`.
pub fn generate_root_ca(state: &mut VhsmState, common_name: &str) -> Result<Vec<u8>, String> {
    if state.pki.ca_certificate.is_some() || state.pki.ca_private_key.is_some() {
        return Err("Root CA already exists".to_string());
    }

    info!("[PKI] Generowanie Root CA rozpoczęte");

    // generate keypair
    let kp = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;

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

/// Sign a public key (SPKI DER) to produce an X.509 certificate signed by the Root CA.
/// `public_key_der` must be SubjectPublicKeyInfo DER bytes.
pub fn sign_public_key(
    state: &VhsmState,
    public_key_der: &[u8],
    common_name: &str,
    is_server: bool,
) -> Result<Vec<u8>, String> {
    info!("[PKI] CSR signing rozpoczęty");

    let ca_cert = match &state.pki.ca_certificate {
        Some(c) => c,
        None => return Err("Root CA not initialized".to_string()),
    };

    let ca_key = match &state.pki.ca_private_key {
        Some(k) => k,
        None => return Err("Root CA private key missing".to_string()),
    };

    // NOTE: full CSR/SPKI signing is not implemented yet. Implementing proper CSR parsing
    // and creating a certificate from a provided public key requires additional careful
    // handling and possibly crates for CSR parsing. For now, return not implemented.
    Err("SignCertificate not implemented yet".to_string())
}
