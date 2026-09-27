# vhsm-daemon

Virtual Hardware Security Module (vHSM) daemon responsible for isolated cryptographic operations, Master Key management ceremonies, and Public Key Infrastructure (PKI) operations.

## Features

- **Master Key Management (SSS):** Master key generation and recovery using Shamir's Secret Sharing scheme.
- **Envelope Encryption:** Generation and wrapping of Key Encryption Keys (KEK) and Data Encryption Keys (DEK) via AES-256-GCM.
- **PKI Infrastructure:** Root CA initialization (ECDSA P-256), encrypted CA private key loading, and intermediate certificate issuance (CSR/X.509).
- **Memory Protection:** Automatic memory zeroization of sensitive key material using `Zeroize` / `Zeroizing` traits.
- **Cryptography:** Support for AES-256-GCM, ECDSA P-256, X.509 certificates, and ASN.1/DER encoding.

## Supported Commands (HsmRequest)

| Command               | Description                                                                     |
| --------------------- | ------------------------------------------------------------------------------- |
| `Ping` / `Status`     | Checks daemon health and retrieves the active key version.                      |
| `GenerateCeremony`    | Initiates a new SSS ceremony (splits a newly generated Master Key into shares). |
| `InitMasterKey`       | Unlocks the daemon by reconstructing the Master Key from a threshold of shares. |
| `GenerateKek`         | Generates a new KEK wrapped with the Master Key.                                |
| `GenerateDataKey`     | Generates a DEK (returns plaintext DEK and KEK-wrapped DEK).                    |
| `GenerateRandomBytes` | Generates cryptographically secure random byte streams.                         |
| `InitRootCa`          | Creates a new self-signed Root CA and encrypts its private key.                 |
| `LoadRootCa`          | Decrypts and loads an active CA private key into daemon memory.                 |
| `SignIntermediateCa`  | Signs incoming CSR requests and issues intermediate certificates.               |
