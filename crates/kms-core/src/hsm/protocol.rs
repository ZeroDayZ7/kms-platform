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
        shares: Vec<(u8, String)>,
    },
    GenerateKek {
        algorithm: String,
    },
    GenerateDataKey {
        wrapped_kek: Vec<u8>,
        kek_version: Option<u32>,
        algorithm: String,
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
        shares: Vec<(u8, String)>,
    },
    MasterKeyInitialized,
    KekGenerated {
        wrapped_kek: Vec<u8>,
        kek_version: u32,
        root_key_version: u32,
        algorithm: String,
    },
    DataKeyGenerated {
        plaintext_dek: Vec<u8>,
        wrapped_dek: Vec<u8>,
        kek_version: u32,
        root_key_version: u32,
    },
    Encrypted {
        ciphertext: Vec<u8>,
        key_version: u32,
    },
    Decrypted {
        plaintext: Vec<u8>,
        key_version: u32,
    },
    Error {
        code: u16,
        message: String,
    },
}
