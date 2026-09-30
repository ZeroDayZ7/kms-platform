# KMS Platform Architecture Rules

## Module Boundaries & Responsibilities

- `kms-db`: Raw database models, migrations, and low-level SQLx queries. NO business logic.
- `kms-core`: Pure cryptographic primitives, core domain models, and audit hash calculation algorithms. ZERO DB/HTTP dependencies.
- `kms-service`: Main REST/gRPC API service layer and orchestration. Contains use-cases and request handlers.
- `kms-ceremony-cli`: Thin CLI client execution wrapper. Contains NO DB logic, NO business logic. Communicates ONLY via HTTP endpoints to `kms-service`.

## Single Source of Truth Rules

- `audit_logs` is the ONLY source of truth for ceremonies, security events, and key lifecycle state transitions.
- NEVER create redundant status tables for events that belong in `audit_logs` (e.g. `ceremonies`).
- NEVER write mock/no-op functions in `kms-db` repositories to hide missing tables or bypass logic.

## Code & Refactoring Standards

- Idiomatic Rust with ZERO compiler warnings (`#![deny(warnings)]`).
- Functional approach for exported functions (standalone functions over huge service structs).
