use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HsmRequest {
    Ping,
    Status,
    InitMasterKey {
        threshold: u8,
        shares: Vec<String>,
    },
    Encrypt {
        key_id: String,
        key_version: Option<u32>,
        plaintext: Vec<u8>,
    },
    Decrypt {
        key_id: String,
        key_version: Option<u32>,
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HsmResponse {
    Pong,
    StatusInfo {
        initialized: bool,
        active_key_version: u32,
    },
    Initialized,
    Encrypted {
        ciphertext: Vec<u8>,
    },
    Decrypted {
        plaintext: Vec<u8>,
    },
    Error {
        code: u16,
        message: String,
    },
}
