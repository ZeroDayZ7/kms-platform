# KMS Platform

An enterprise-grade, microservice-based Key Management System (KMS) written in Rust, designed for secure key lifecycle management, envelope encryption, and virtualized HSM hardware isolation.

## Architecture Overview

The platform is structured as a Rust workspace composed of decoupled, single-responsibility crates separating shared cryptographic primitives, core API services, ceremony tooling, and virtual HSM daemons.

| Component              | Type            | Primary Responsibility                                                                                                              |
| :--------------------- | :-------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| **`kms-core`**         | Shared Library  | Domain models, serialization primitives, SSS algorithms, IPC framing protocols, and shared cryptographic primitives.                |
| **`kms-service`**      | Core Service    | High-level API managing Data Encryption Key (DEK) lifecycle, key rotation, versioning, and cryptographic delegation.                |
| **`vhsm-daemon`**      | Isolated Daemon | Virtual Hardware Security Module (vHSM) managing root key reconstruction in memory and processing crypto commands over IPC sockets. |
| **`kms-ceremony-cli`** | CLI Utility     | Operational tool for executing zero-trust key generation ceremonies and splitting master secrets into SSS shares.                   |

---

## Key Cryptographic Concepts & Design

- **Dual Master Key Provider Engine:**
  - **`local` Mode:** `kms-service` loads master key material directly into service memory. Suitable for standalone deployments or development environments.
  - **`hsm` Mode:** `kms-service` retains zero knowledge of the master keys. All cryptographic operations (encrypt/decrypt/rewrap) are delegated via IPC socket directly to the `vhsm-daemon`.

- **Isolated Virtual HSM (vHSM):**
  - Operates as a separate daemon process listening on Unix Domain Sockets (with abstract transport boundaries for IPC/TCP extension).
  - Enforces a deterministic 4-byte big-endian length-prefixed binary message framing protocol for safe payload parsing.
  - Maintains root key material strictly in-memory (`RAM`) with secure zeroization on process termination or reset.

- **Shamir's Secret Sharing (SSS) Ceremony:**
  - Root master keys are generated during formal key ceremonies using `kms-ceremony-cli`.
  - Secrets are split into $N$ key shares with an $M$-of-$N$ threshold requirement.
  - Unlocking the `vhsm-daemon` requires submitting the valid $M$ threshold shares via the `InitMasterKey` protocol request.
