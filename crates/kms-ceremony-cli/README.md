# KMS Ceremony CLI

An offline Command-Line Interface (CLI) utility written in Rust for executing Key Management Service (KMS) key ceremonies. The tool generates cryptographic master and storage keys, splits secrets using Shamir's Secret Sharing Scheme (SSSS), and recovers master keys from active shares.

## Features

- **Shamir's Secret Sharing (SSSS)**: Split master keys into configurable total shares ($N$) and recovery thresholds ($T$).

- **AES-256-GCM Encryption**: Securely encrypt storage key containers using generated master keys.

- **Ceremony Audit Manifest**: Automatically produce structured JSON manifests containing metadata, cryptographic nonces, and ciphertext records.

- **Interactive Mode**: Guided terminal walkthrough for interactive key generation and recovery operations.

- **Zeroization**: Sensitive cryptographic key byte arrays in memory are automatically zeroized on drop.

---

## Usage Syntax

```text
kms-ceremony-cli [COMMAND] [OPTIONS]

```

### Available Commands

- `generate`: Generates a master key, storage key, SSSS shares, and a ceremony manifest.

- `recover`: Reconstructs the master key using a directory containing valid share JSON files.

- `interactive`: Starts an interactive terminal walkthrough.

---

## Operation Guides

### 1. Execute Key Generation Ceremony

To generate a master key split into 5 shares with a recovery threshold of 3:

```bash
kms-ceremony-cli generate --shares 5 --threshold 3 --output-dir ./out

```

**Options**:

- `-s, --shares <NUMBER>`: Total number of SSSS shares to generate (default: `5`).

- `-t, --threshold <NUMBER>`: Minimum shares required for recovery (default: `3`).

- `-o, --output-dir <DIR>`: Output directory path for shares and manifest (default: `./out`).

**Generated Output Directory Structure**:

```text
out/
├── ceremony_manifest.json
└── shares/
    ├── share_1.json
    ├── share_2.json
    ├── share_3.json
    ├── share_4.json
    └── share_5.json

```

---

### 2. Recover Master Key from Shares

To recover the original master key, point the command to the directory containing at least $T$ valid share JSON files:

```bash
kms-ceremony-cli recover --shares-dir ./out/shares --output-key ./recovered.key

```

**Options**:

- `-d, --shares-dir <DIR>`: Directory containing share JSON files (default: `./out/shares`).

- `-k, --output-key <FILE>`: File path to store the recovered hex-encoded key (default: `./recovered.key`).

---

### 3. Interactive Mode

Run the interactive step-by-step CLI prompt:

```bash
kms-ceremony-cli

```

Or explicitly pass the subcommand:

```bash
kms-ceremony-cli interactive --output-dir ./out

```

---

## Manifest and Share Structure

### Ceremony Manifest (`ceremony_manifest.json`)

Contains ceremony metadata, parameter limits, share filenames, and the encrypted storage key container:

```json
{
  "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "version": 1,
  "created_at": "2026-08-18T20:00:00Z",
  "threshold": 3,
  "total_shares": 5,
  "share_files": [
    "share_1.json",
    "share_2.json",
    "share_3.json",
    "share_4.json",
    "share_5.json"
  ],
  "encrypted_storage_key_nonce": "a1b2c3d4e5f6789012345678",
  "encrypted_storage_key_ciphertext": "9f8e7d6c5b4a..."
}
```

### Share File (`share_X.json`)

Encapsulates an individual share with SHA-256 integrity metadata:

```json
{
  "index": 1,
  "threshold": 3,
  "total_shares": 5,
  "share_hex": "1-a3f...",
  "share_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "created_at": "2026-08-18T20:00:00Z"
}
```
