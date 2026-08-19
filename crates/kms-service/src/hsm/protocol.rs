use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HsmRequest {
    Ping,
    Encrypt { key_id: String, plaintext: Vec<u8> },
    Decrypt { key_id: String, ciphertext: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HsmResponse {
    Pong,
    Encrypted { ciphertext: Vec<u8> },
    Decrypted { plaintext: Vec<u8> },
    Error { code: u16, message: String },
}
