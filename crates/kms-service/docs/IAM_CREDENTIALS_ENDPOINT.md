# IAM Credentials Endpoint Specification

## Overview

Endpoint służy do weryfikacji tożsamości serwisów/agentów (np. sidecara `Secret-Agent`) oraz wydawania poświadczeń dostępnych w oparciu o zdefiniowane polityki IAM (`iam_credentials_policy.json`).

---

## 1. Authentication & Security Policy

- **Transport:** HTTPS / TLS (opcjonalnie mTLS wewnątrz klastra/mesh).
- **Client Auth:** W zależności od konfiguracji klienta (np. `Bearer <Token>`, klucz serwisu `X-Service-Api-Key` lub podpisany token JWT).
- **Rate Limiting:** Objęty globalnym limiterem KMS opartym o Redis / InMemory.

---

## 2. API Specification

### POST `/api/v1/iam/credentials/issue`

Służy do wymiany poświadczeń serwisu na tymczasowe poświadczenia dostępowe / tokeny sesyjne.

#### Request Headers

```http
Content-Type: application/json
X-Service-Id: payment-service
Authorization: Bearer <service_bootstrap_token>
```
