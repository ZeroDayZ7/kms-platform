use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HsmRequest {
    Ping,
    Status,
    // Nowe żądanie: demon generuje klucz i zwraca udziały
    GenerateCeremony {
        threshold: u8,
        total_shares: u8,
    },
    // Stare InitMasterKey zostawiamy np. do odzyskiwania
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HsmResponse {
    Pong,
    StatusInfo {
        initialized: bool,
        active_key_version: u32,
    },
    // Odpowiedź z udziałami wygenerowanymi wewnątrz HSM
    CeremonyGenerated {
        shares: Vec<(u8, String)>, // (index, hex_value)
    },
    MasterKeyInitialized,
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