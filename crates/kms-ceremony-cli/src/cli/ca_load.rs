use anyhow::Result;
use kms_core::hsm::client::load_root_ca_via_hsm;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;

pub async fn handle_ca_load(socket_path: String, ca_tag: String, encrypted_b64: String) -> Result<()> {
    let encrypted = BASE64_ENGINE.decode(&encrypted_b64)?;
    load_root_ca_via_hsm(&socket_path, &ca_tag, &encrypted, None).await?;
    println!("CA '{}' loaded into vHSM", ca_tag);
    Ok(())
}
