# KMS Platform

A Rust-based mono-repo Key Management System built to stop keys from floating around as plaintext in configurations and databases. Powered by microservices, vHSM isolation, and Shamir's ceremonies.

<p align="center">
  <img src="docs/assets/banner.png" alt="KMS Platform Architecture" />
</p>

## Workspace Layout

| Component              | Role        | What it does                                                                              |
| :--------------------- | :---------- | :---------------------------------------------------------------------------------------- |
| **`kms-core`**         | Library     | Shared models, SSS (Shamir's Secret Sharing), IPC protocol, and cryptographic primitives. |
| **`kms-service`**      | API Service | Lifecycle management for DEK/KEK, key rotation, and versioning.                           |
| **`vhsm-daemon`**      | vHSM Daemon | Isolated process holding the master key strictly in RAM; handles IPC over sockets.        |
| **`kms-ceremony-cli`** | CLI Utility | Executes key split ceremonies and generates operator shares.                              |

---

## Architecture & Security

- **Master Key Providers:**
  - **`local`**: Dev/standalone mode (direct access to the key within the service).(deprecated)
  - **`hsm`**: Zero-trust mode. `kms-service` has zero knowledge of the master key; every cryptographic operation is delegated via Unix Socket to `vhsm-daemon`.

- **Virtual HSM (vHSM):**
  - Runs as an isolated process with memory sandboxing.
  - Binary communication based on a length-prefixed protocol (4-byte big-endian header).
  - Zero disk persistence for the root key; requires a formal ceremony unlock sequence.

- **Shamir's Secret Sharing (SSS) Ceremony:**
  - The root master key is generated and split into $N$ shares with an $M$-of-$N$ threshold requirement.
  - Unlocking the `vhsm-daemon` requires submitting the required number of valid, decrypted-on-the-fly shares via the CLI.
