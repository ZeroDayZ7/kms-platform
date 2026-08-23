# Dokumentacja API i Instrukcja Użycia KMS Service

Dokumentacja usługi Key Management Service (KMS) zawierająca opisy endpointów HTTP, mechanizmu autoryzacji HMAC, przykładów użycia (cURL, Bash) oraz komend CLI.

---

## Adres Bazowy (Base URL)

- **Lokalny rozwój:** `http://127.0.0.1:7000` (lub `http://localhost:8080` w Dockerze)

---

## Autoryzacja i Nagłówki HTTP (HMAC Authentication)

Wszystkie chronione endpointy usługi KMS wymagają nagłówków autoryzacyjnych opartych na podpisie **HMAC-SHA256**:

- `X-Service-Name` – identyfikator serwisu wywołującego (np. `auth-service`, `gateway-service`)
- `X-Timestamp` – stempel czasowy Unix (np. `1770000000`)
- `X-HMAC-Signature` – podpis w formacie hex wyliczony wg wzoru:

$$\text{podpis} = \text{HMAC-SHA256}(\text{SECRET}, \text{"METHOD:PATH:TIMESTAMP"})$$

### Przykład wyliczenia podpisu HMAC w Bash:

```bash
SERVICE_NAME="auth-service"
SECRET="super-long-random-secret-for-auth-service-hmac-64-bytes"
METHOD="POST"
PATH_URI="/api/v1/keys/private"
TIMESTAMP=$(date +%s)

PAYLOAD="${METHOD}:${PATH_URI}:${TIMESTAMP}"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/(stdin)= //')

echo "Timestamp: $TIMESTAMP"
echo "Signature: $SIGNATURE"
```

---

## Format Błędów

W przypadku niepowodzenia endpointy zwracają odpowiednie kody statusu HTTP oraz strukturę JSON:

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Błędne dane wejściowe: HTTP rewrap is disabled by server configuration",
  "details": "HTTP rewrap is disabled by server configuration"
}
```

### Kody błędów:

- `AUTH_FAILED` (401 Unauthorized) – nieprawidłowy podpis HMAC lub brak uprawnień ACL
- `RESOURCE_NOT_FOUND` (404 Not Found) – brak klucza dla danego serwisu
- `VALIDATION_ERROR` (400 Bad Request) – nieprawidłowe parametry
- `CONFLICT_ERROR` (409 Conflict) – konflikt w bazie danych
- `CRYPTO_FAILURE` (422 Unprocessable Entity) – błąd odszyfrowywania/szyfrowania
- `INTERNAL_SERVER_ERROR` (500 Internal Server Error) – wewnętrzny błąd serwera

---

## Przykłady Użycia Endpointów HTTP

### 1. Sprawdzanie Stanu Usługi (Health Check)

**Endpoint:** `GET /health`  
_Nie wymaga autoryzacji HMAC._

```bash
curl -X GET http://127.0.0.1:7000/health
```

**Odpowiedź (200 OK):**

```json
{
  "status": "ok"
}
```

---

### 2. Generowanie Nowego Klucza (Generate Key)

**Endpoint:** `POST /api/v1/keys/generate`

**Wymagane nagłówki:**

- `Content-Type: application/json`
- `X-Service-Name`, `X-Timestamp`, `X-HMAC-Signature`

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "service_id": "auth-service",
    "algorithm": "Ed25519",
    "purpose": "Signing"
  }'
```

**Dostępne algorytmy (`algorithm`):**

- `Ed25519` (podpisywanie cyfrowe)
- `X25519` (wymiana kluczy / szyfrowanie)
- `AES256GCM` (symetryczne szyfrowanie danych)
- `HmacSha256` (symetryczna autentykacja)

**Dostępne cele (`purpose`):**

- `Signing`
- `Encryption`
- `Authentication`

**Odpowiedź (200 OK):**

```json
{
  "id": "018f3a5b-7c8d-7123-8123-456789abcdef",
  "service_id": "auth-service",
  "algorithm": "Ed25519",
  "purpose": "Signing",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
  "version": 1,
  "status": "Active",
  "created_at": "2026-08-14T12:00:00Z"
}
```

---

### 3. Pobieranie Klucza Publicznego (Get Public Key)

**Endpoint:** `GET /api/v1/keys/public/{service_id}/{algorithm}`

**Przykład cURL:**

```bash
curl -X GET http://127.0.0.1:7000/api/v1/keys/public/auth-service/Ed25519 \
  -H "X-Service-Name: gateway-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>"
```

**Odpowiedź (200 OK):**

```json
{
  "id": "018f3a5b-7c8d-7123-8123-456789abcdef",
  "service_id": "auth-service",
  "algorithm": "Ed25519",
  "purpose": "Signing",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
  "version": 1,
  "status": "Active",
  "created_at": "2026-08-14T12:00:00Z"
}
```

---

### 4. Pobieranie Odszyfrowanego Klucza Prywatnego (Get Private Key)

**Endpoint:** `POST /api/v1/keys/private`

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/private \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "service_id": "shared-jwt",
    "algorithm": "Ed25519"
  }'
```

**Odpowiedź (200 OK):**

```json
{
  "service_id": "shared-jwt",
  "algorithm": "Ed25519",
  "version": 1,
  "private_key_b64": "MIIB..."
}
```

---

### 5. Pobieranie Odszyfrowanego Klucza Symetrycznego (Get Symmetric Key)

**Endpoint:** `POST /api/v1/keys/symmetric`

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/symmetric \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: citizen-docs-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "service_id": "docs-id-cards",
    "algorithm": "AES256GCM"
  }'
```

**Odpowiedź (200 OK):**

```json
{
  "service_id": "docs-id-cards",
  "algorithm": "AES256GCM",
  "version": 1,
  "key_b64": "s+g4w2B+N6O9m7YQ..."
}
```

---

### 6. Rotacja Klucza (Rotate Key)

**Endpoint:** `POST /api/v1/keys/rotate`

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/rotate \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "service_id": "auth-service",
    "algorithm": "Ed25519",
    "reason": "Scheduled",
    "actor_id": "admin-user-1"
  }'
```

**Możliwe powody rotacji (`reason`):**

- `Scheduled` (planowana rotacja, stary klucz przechodzi w stan `Deprecated` na okres przejściowy)
- `Manual` (reczna rotacja)
- `Compromised` (naruszenie bezpieczeństwa, stary klucz zostaje natychmiast oznaczony jako `Compromised`)

**Odpowiedź (200 OK):**

```json
{
  "id": "018f3a5c-1122-3344-5566-778899aabbcc",
  "service_id": "auth-service",
  "algorithm": "Ed25519",
  "purpose": "Signing",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "version": 2,
  "status": "Active",
  "created_at": "2026-08-14T12:30:00Z"
}
```

---

### 7. Szyfrowanie Kopertowe KMS (Encrypt Data)

**Endpoint:** `POST /api/v1/encrypt`

Szyfruje przekazane bajty za pomocą aktywnego klucza Master Key KMS.

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "plaintext": "VGVzdG93eSB0ZXh0"
  }'
```

**Odpowiedź (200 OK):**

```json
{
  "ciphertext": "7Fh7q2q6ZV6w9Q==",
  "master_key_version": 1
}
```

---

### 8. Odszyfrowanie Kopertowe KMS (Decrypt Data)

**Endpoint:** `POST /api/v1/decrypt`

Odszyfrowuje szyfrogram używając Master Key KMS w odpowiedniej wersji.

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "ciphertext": "7Fh7q2q6ZV6w9Q==",
    "master_key_version": 1
  }'
```

**Odpowiedź (200 OK):**

```json
{
  "plaintext": "VGVzdG93eSB0ZXh0"
}
```

---

### 9. Przepakowanie Kluczy Admina (HTTP Rewrap Keys)

**Endpoint:** `POST /api/v1/admin/kms/rewrap`

_Uwaga: Wymaga włączonej flagi konfiguracyjnej `enable_http_rewrap = true` w `config/settings.toml` lub zmiennej środowiskowej `CRYPTO__ENABLE_HTTP_REWRAP=true`._

**Przykład cURL:**

```bash
curl -X POST http://127.0.0.1:7000/api/v1/admin/kms/rewrap \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "target_version": 2,
    "batch_size": 100
  }'
```

**Odpowiedź gdy włączone (200 OK):**

```json
{
  "rewrapped": 12,
  "target_version": 2,
  "batch_size": 100
}
```

**Odpowiedź gdy wyłączone (400 Bad Request):**

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Błędne dane wejściowe: HTTP rewrap is disabled by server configuration",
  "details": "HTTP rewrap is disabled by server configuration"
}
```

---

### 10. Zdalne Podpisywanie Danych / JWT (Sign Data)

**Endpoint:** `POST /api/v1/keys/sign`

Umożliwia bezbieczne podpisywanie ciągów danych (np. bajtów `header.payload` tokena JWT) wewnątrz KMS. Klucz prywatny nie opuszcza pamięci KMS (Zero-Trust isolation).

**Wymagane nagłówki:**

- `Content-Type: application/json`
- `X-Service-Name`, `X-Timestamp`, `X-HMAC-Signature`

**Parametry żądania (`body`):**

- `target_service` (string, wymagane) – identyfikator kluczadocelowego w ACL (np. `"shared-jwt"`)
- `algorithm` (string, wymagane) – algorytm podpisu (np. `"Ed25519"`)
- `payload_b64` (string, wymagane) – dane do podpisania zakodowane w formacie Base64
- `key_version` (number, opcjonalne) – konkretna wersja klucza; jeśli `null`, KMS użyje aktywnego klucza

**Przykład cURL:**

```bash
curl -X POST [http://127.0.0.1:7000/api/v1/keys/sign](http://127.0.0.1:7000/api/v1/keys/sign) \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 1770000000" \
  -H "X-HMAC-Signature: <wyliczony_podpis_hmac>" \
  -d '{
    "target_service": "shared-jwt",
    "algorithm": "Ed25519",
    "payload_b64": "ZXlKaGJHY2lPaUpUVXpVTz...",
    "key_version": null
  }'

```

**Odpowiedź (200 OK):**

```json
{
  "signature_b64": "dGhpcyBpcyBhIHNpZ25hdHVyZQ...",
  "key_version": 1,
  "algorithm": "Ed25519"
}
```

---

## Interfejs Wiersza Poleceń (CLI Commands)

Aplikacja wspiera również bezpośrednie wykonywanie zadań z poziomu terminala bez konieczności uruchamiania serwera HTTP.

### 1. Uruchomienie Serwera HTTP

```bash
cargo run -- serve
```

lub po zbudowaniu binarki:

```bash
./kms-service serve
```

### 2. Inicjalizacja / Bootstrap Kluczy

Tworzy brakujące klucze wymagane przez konfigurację ACL w bazie MongoDB:

```bash
cargo run -- bootstrap
```

### 3. Rewrap Kluczy z Poziomu Terminala

Bezpieczne przepakowywanie kluczy zaszyfrowanych starszą wersją Master Key do nowej wersji z poziomu CLI (zalecany sposób):

```bash
cargo run -- rewrap --target-version 2 --batch-size 100
```

Parametry:

- `--target-version` (wymagany): docelowa wersja Master Key
- `--batch-size` (opcjonalny, domyślnie 100): rozmiar paczki przetwarzanych kluczy
