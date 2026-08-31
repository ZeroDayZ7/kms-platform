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
    /// Generate a Root CA and return the CA certificate (DER)
    GenerateRootCA {
        common_name: String,
    },
    /// Sign a provided SubjectPublicKeyInfo (DER) and return signed certificate
    SignCertificate {
        csr: Vec<u8>,
        is_server: bool,
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
    RootCAGenerated {
        ca_certificate: Vec<u8>,
    },
    CertificateSigned {
        certificate: Vec<u8>,
        ca_certificate: Vec<u8>,
    },
    Error {
        code: u16,
        message: String,
    },
}
