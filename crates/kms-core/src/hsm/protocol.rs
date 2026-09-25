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
    GenerateRandomBytes {
        length: usize,
    },
    GenerateCredential {
        password_length: usize,
    },
    /// Initialize a Root CA fully inside vHSM: generate keypair, build & sign self-signed cert,
    /// encrypt private key with master/root key and return encrypted blob + public cert material.
    InitRootCa {
        ca_tag: String,
        common_name: String,
        validity_days: u32,
        algorithm: String,
    },
    /// Load an encrypted Root CA private key into vHSM RAM (after unseal). The encrypted blob
    /// must have been produced by `InitRootCa` or a compatible wrapping operation.
    LoadRootCa {
        ca_tag: String,
        encrypted_private_key: Vec<u8>,
    },
    /// Sign an intermediate CSR using a loaded Root CA identified by `ca_tag`.
    SignIntermediateCa {
        ca_tag: String,
        csr_pem: String,
        validity_days: u32,
    },
    /// Generate a Root CA private/public keypair inside vHSM. Returns only encrypted private key and public data.
    GenerateRootCaKey {
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
    RandomBytesGenerated {
        random_bytes: Vec<u8>,
    },
    Encrypted {
        ciphertext: Vec<u8>,
        key_version: u32,
    },
    Decrypted {
        plaintext: Vec<u8>,
        key_version: u32,
    },
    CredentialGenerated {
        credential_id: String,
        password: String,
        wrapped_password: Vec<u8>,
        key_version: u32,
    },
    /// Response when a Root CA key was generated inside vHSM.
    RootCaKeyGenerated {
        encrypted_private_key: Vec<u8>,
        public_key: Vec<u8>,
        master_key_version: u32,
        algorithm: String,
    },
    Error {
        code: u16,
        message: String,
    },
}
