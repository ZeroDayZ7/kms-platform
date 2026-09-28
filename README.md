# KMS Platform

Rust-based Key Management System for managing cryptographic keys, credentials, and key lifecycle without keeping master keys in application configuration or databases.

KMS is built as a microservice platform with an isolated vHSM, Shamir's Secret Sharing ceremonies, and upstream Public Key Infrastructure (PKI) authority integration.

## Workspace

| Component                           | Role           | Description                                                                                                           |
| ----------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------- |
| **`kms-core`**                      | Library        | Shared domain models, cryptography, Shamir's Secret Sharing, and IPC protocol.                                        |
| **`kms-db`**                        | Library        | Database access layer and repositories used by KMS services.                                                          |
| **`kms-service`**                   | API Service    | Manages keys, KEKs, DEKs, credentials, rotation, and key versions.                                                    |
| **`kms-migrate`**                   | Migration Tool | Applies database migrations and exits.                                                                                |
| **`vhsm-daemon`**                   | vHSM           | Isolated process that keeps the master key in RAM and performs cryptographic operations.                              |
| **`kms-ceremony-cli`**              | CLI            | Performs key ceremonies, unlocks the vHSM, and manages bootstrap operations.                                          |
| **`vspire-kms-upstream-authority`** | Upstream CA    | Integrates with upstream Certificate Authorities to manage PKI trust chains and issue intermediate/leaf certificates. |

## Architecture

The system separates key management from applications that use the keys.

- `kms-service` does not directly hold the master key when running in HSM mode.
- `vhsm-daemon` keeps the master key in RAM and performs operations requiring it.
- `vspire-kms-upstream-authority` handles communication and certificate signing requests with external or internal upstream Root/Intermediate CAs.
- Communication with the vHSM uses a Unix domain socket and a length-prefixed IPC protocol.
- Cryptographic keys are stored in encrypted/wrapped form rather than as plaintext master keys.
- Key versions and lifecycle are managed by KMS.
- Sensitive credentials can be provisioned and rotated through KMS.
- Audit records are maintained for security-sensitive operations.

## Master Key

The master key is protected by the vHSM.

The key is generated during a ceremony and split using **Shamir's Secret Sharing** into `N` shares with an `M-of-N` threshold.

The vHSM is unlocked by providing the required number of valid shares through `kms-ceremony-cli`.

The master key is never persisted to disk by the vHSM.

## Startup Sequence

After starting the platform, the initialization order is:

1. **Migrate** — apply database migrations.
2. **Unlock** — unlock the vHSM using the required Shamir shares.
3. **Bootstrap** — import initial encrypted credentials, resources, and CA trust chains into KMS.

Development commands:

```bash
make migrate-dev
make unlock-dev
make bootstrap-dev

```

Standard environment commands:

```bash
make migrate
make unlock
make bootstrap

```

## Development

The development environment uses Docker Compose with Rust `cargo run` and shared persistent Docker networks.

```bash
make dev

```

Development shutdown:

```bash
make dev-down

```

The development shutdown removes Compose-managed volumes but leaves the shared external Docker networks intact.

## Security Model

The security model separates application services, secret management, upstream authority integration, and the master key.

Target architecture:

```text
Application Service
       │
       │ local IPC
       ▼
 secret-agent
       │
       │ KMS API
       ▼
  kms-service ──────────► vspire-kms-upstream-authority (Upstream CA / PKI)
       │
       │ Unix IPC
       ▼
  vhsm-daemon
       │
       ▼
   Master Key (RAM only)

```

**`secret-agent`** is designed as a Rust-based sidecar running alongside application services. It provides services with secure access to secrets without requiring applications to manage sensitive credentials directly.

**`vspire-kms-upstream-authority`** bridges `kms-service` and upstream certificate authorities to enforce trust chain hierarchy, handle certificate signing requests (CSR), and maintain PKI identity integration.

The `kms-service` manages keys, credentials, and their lifecycle, while `vhsm-daemon` provides the isolated cryptographic boundary and keeps the master key in RAM.

The master key is not required to be present in application configuration, databases, or application environments. Operator access to the master key is strictly controlled through the Shamir Secret Sharing ceremony.
