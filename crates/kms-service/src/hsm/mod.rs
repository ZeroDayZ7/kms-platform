pub mod client;
pub mod protocol;

pub use client::{decrypt_via_hsm, encrypt_via_hsm, send_hsm_request};
pub use protocol::{HsmRequest, HsmResponse};
