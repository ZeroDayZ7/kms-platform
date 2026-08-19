use kms_core::hsm::client::{
    decrypt_via_hsm as core_decrypt, encrypt_via_hsm as core_encrypt, send_hsm_request as core_send,
};
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::errors::AppResult;

pub async fn send_hsm_request(socket_path: &str, req: &HsmRequest) -> AppResult<HsmResponse> {
    core_send(socket_path, req).await.map_err(Into::into)
}

pub async fn encrypt_via_hsm(
    socket_path: &str,
    key_id: &str,
    key_version: Option<u32>,
    plaintext: &[u8],
) -> AppResult<Vec<u8>> {
    core_encrypt(socket_path, key_id, key_version, plaintext)
        .await
        .map_err(Into::into)
}

pub async fn decrypt_via_hsm(
    socket_path: &str,
    key_id: &str,
    key_version: Option<u32>,
    ciphertext: &[u8],
) -> AppResult<Vec<u8>> {
    core_decrypt(socket_path, key_id, key_version, ciphertext)
        .await
        .map_err(Into::into)
}
