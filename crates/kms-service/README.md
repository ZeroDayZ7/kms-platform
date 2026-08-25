# kms-service

**Production-style Key Management Service (KMS) written in Rust** built with **Axum + Tokio**, designed as a secure, high-performance microservice for cryptographic key operations and secret lifecycle management.

This project demonstrates **enterprise-grade Hexagonal / Clean Architecture** with strong separation of concerns (domain / application / infrastructure), Envelope Encryption, asymmetric key pair generation, structured configuration, observability, and distributed rate limiting.

---

## Highlights

- **Async HTTP API** powered by **Axum (0.8)** + **Tokio**
- **Clean Architecture approach**
  - `domain` defines core contracts (ports), entities, and cryptographic interfaces
  - `application` implements isolated Use Cases (`UnlockSecretUseCase`, etc.)
  - `infrastructure` provides MongoDB / Redis adapters and cryptographic implementations
- **Enterprise-Grade KMS & Security**
  - **Envelope Encryption** using **AES-256-GCM** with a 32-byte Master Key
  - **Shamir's Secret Sharing (SSS) & Key Ceremony** for split Master Key generation and threshold-based quorum reconstruction
  - **Dynamic Emergency Lock System** allowing instant Master Key purging from memory via administrative endpoints (`/admin/ceremony/lock`)
  - Asymmetrical key pair generation for **Ed25519** (Digital Signatures) and **X25519** (Key Exchange)
  - Memory-safe key handling with `ZeroizeOnDrop`
- **MongoDB integration** with repository pattern (`MongoVaultRepository`, `MongoUserRepository`)
- **Redis integration** (Fred client) for caching and distributed rate limiting
- **Two-level rate limiting**
  - In-memory governor-based limits (`tower-governor`)
  - Redis-backed limiter using **Lua script + EVALSHA optimization**
- **Security middleware**
  - CSP, XSS protection, strict transport security, nosniff, frame deny
- **Structured logging**
  - Console logs + JSON file logging with `tracing` spans and request tracing middleware
- **Graceful shutdown** with configurable timeout

[![Rust](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

---

## Documentation

Detailed technical specifications and operational guides can be found in the [`docs/`](./docs) directory:

- [**Lock & SSS Feature Architecture**](./docs/LOCK_FEATURE.md) – Detailed flow of Shamir's Secret Sharing, state management, and lock/unlock mechanisms.
- [**Bootstrap & Ceremony Guide**](./docs/BOOTSTRAP_GUIDE.md) – Step-by-step instructions for initial environment setup and key ceremony execution.
- [**CLI Tool Usage**](./docs/CLI.md) – Manual for command-line management and operator commands.
- [**API Specification**](./docs/API.md) – Full HTTP API endpoint documentation and schema definitions.
