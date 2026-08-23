## 1. Założenia bezpieczeństwa

- Klucze prywatne nie opuszczają KMS przez interfejs REST API.
- Endpoint `POST /api/v1/keys/private` został usunięty z publicznej specyfikacji API i nie jest dostępny do użytku produkcyjnego.
- Wszystkie chronione endpointy wymagają podpisu HMAC-SHA256 z dodatkowymi polami:
  - `X-Service-Name`
  - `X-Timestamp`
  - `X-Nonce`
  - `X-Body-SHA256`
  - `X-HMAC-Signature`
- Żądania z powtórzonym nonce, niepoprawnym timestampem lub niedopasowanym podpisem są odrzucane jako nieautoryzowane.

---

## 2. Adres bazowy

- Lokalny development: `http://127.0.0.1:7000`
- Docker / środowisko integracyjne: `http://localhost:8080`

---

## 3. Uwierzytelnianie HMAC — wymagania dla żądań

Wszystkie endpointy chronione wymagają nagłówków:

- `X-Service-Name`: identyfikator serwisu wywołującego
- `X-Timestamp`: znacznik czasu w formacie RFC3339 / ISO 8601
- `X-Nonce`: unikalny identyfikator żądania, generowany per request
- `X-Body-SHA256`: hex SHA-256 z treści body żądania
- `X-HMAC-Signature`: hex podpisu HMAC-SHA256

Wzór podpisu:

```text
HMAC-SHA256(secret, "METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256")
```

Przykład:

```bash
SERVICE_NAME="auth-service"
SECRET="super-long-random-secret-for-auth-service-hmac-64-bytes"
METHOD="POST"
PATH_URI="/api/v1/keys/sign"
TIMESTAMP="2026-08-23T12:00:00Z"
NONCE="7fe2d8a9-6420-4891-9d63-8d1d2f4a61d8"
BODY_SHA256=$(printf '%s' '{"target_service":"shared-jwt","algorithm":"Ed25519"}' | sha256sum | awk '{print $1}')
PAYLOAD="${METHOD}:${PATH_URI}:${TIMESTAMP}:${NONCE}:${BODY_SHA256}"
SIGNATURE=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/(stdin)= //')
```

### 3.1 Ochrona przed atakami replay

Serwer stosuje następujące zabezpieczenia:

- `X-Timestamp` musi być zgodny z akceptowalnym oknem czasowym: ±60 sekund względem czasu serwera.
- `X-Nonce` musi być unikalny w oknie 300 sekund (TTL 5 minut).
- Powtórne użycie tego samego `X-Nonce` dla tego samego `X-Service-Name` zostaje odrzucone jako replay.
- `X-Body-SHA256` jest częścią podpisu, aby uniemożliwić podmianę treści zapytania po wygenerowaniu podpisu.
- W przypadku niepoprawnego, wygasłego lub zduplikowanego nonce / timestampu serwer zwraca `401 Unauthorized`.

### 3.2 Statusy autoryzacji

- `401 Unauthorized`: brak lub błędny nagłówek HMAC, nieprawidłowy podpis, wygasły timestamp, duplikat nonce, timestamp poza oknem czasowym.
- `403 Forbidden`: podpis i timestamp są poprawne, ale żądanie narusza politykę ACL / brak uprawnień do danego zasobu.

---

## 4. Endpointy API

### 4.1 Usunięty endpoint: klucze prywatne

#### `POST /api/v1/keys/private` — usunięty / niedostępny

Status: `Removed`

```yaml
deprecated: true
status: removed
description: >-
  Endpoint usunięty z publicznej specyfikacji API. Klucze prywatne nie mogą być zwracane
  do klienta HTTP. Serwer nie udostępnia ich ani przez REST, ani przez zwykły JSON response.
```

Zakaz:

- eksportu klucza prywatnego do klienta HTTP,
- zwracania klucza prywatnego w formacie Base64 / PEM przez endpoint REST,
- odczytu klucza prywatnego poza wewnętrznym, izolowanym obszarem KMS.

---

### 4.2 Health check

#### `GET /health`

Nie wymaga uwierzytelniania.

```bash
curl -X GET http://127.0.0.1:7000/health
```

Odpowiedź:

```json
{
  "status": "ok"
}
```

---

### 4.3 Generowanie klucza

#### `POST /api/v1/keys/generate`

Wymagane nagłówki:

- `Content-Type`
- `X-Service-Name`
- `X-Timestamp`
- `X-Nonce`
- `X-Body-SHA256`
- `X-HMAC-Signature`

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: 7fe2d8a9-6420-4891-9d63-8d1d2f4a61d8" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "service_id": "auth-service",
    "algorithm": "Ed25519",
    "purpose": "Signing"
  }'
```

Odpowiedź `200 OK`:

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

### 4.4 Pobieranie klucza publicznego

#### `GET /api/v1/keys/public/{service_id}/{algorithm}`

```bash
curl -X GET http://127.0.0.1:7000/api/v1/keys/public/auth-service/Ed25519 \
  -H "X-Service-Name: gateway-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: 01b155c1-a4f3-4a99-820f-4ef4923c8d65" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>"
```

---

### 4.5 Pobieranie klucza symetrycznego

#### `POST /api/v1/keys/symmetric`

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/symmetric \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: citizen-docs-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: 19fe9e31-9007-4db0-b1ab-b4d69412bf3b" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "service_id": "docs-id-cards",
    "algorithm": "AES256GCM"
  }'
```

Odpowiedź `200 OK`:

```json
{
  "service_id": "docs-id-cards",
  "algorithm": "AES256GCM",
  "version": 1,
  "key_b64": "s+g4w2B+N6O9m7YQ..."
}
```

> Uwaga: ten endpoint może zwracać tajny materiał klucza symetrycznego tylko w ściśle kontrolowanych scenariuszach zgodnych z polityką ACL; nie ma on nic wspólnego z eksportem klucza prywatnego asymetrycznego.

---

### 4.6 Rotacja klucza

#### `POST /api/v1/keys/rotate`

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/rotate \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: c22e8137-55a8-419c-9e52-664d62c415a1" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "service_id": "auth-service",
    "algorithm": "Ed25519",
    "reason": "Scheduled",
    "actor_id": "admin-user-1"
  }'
```

---

### 4.7 Szyfrowanie i odszyfrowanie danych

#### `POST /api/v1/encrypt`

#### `POST /api/v1/decrypt`

Wymagane nagłówki:

- `Content-Type`
- `X-Service-Name`
- `X-Timestamp`
- `X-Nonce`
- `X-Body-SHA256`
- `X-HMAC-Signature`

Przykład:

```bash
curl -X POST http://127.0.0.1:7000/api/v1/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: d35f8ab2-b3d7-480b-af01-567cde901f25" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "plaintext": "VGVzdG93eSB0ZXh0"
  }'
```

---

### 4.8 Podpisywanie danych / JWT

#### `POST /api/v1/keys/sign`

```bash
curl -X POST http://127.0.0.1:7000/api/v1/keys/sign \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: e1cc2228-cf75-47cb-8a53-0d2f300b9ff3" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "target_service": "shared-jwt",
    "algorithm": "Ed25519",
    "payload_b64": "ZXlKaGJHY2lPaUpUVXpVTz...",
    "key_version": null
  }'
```

---

### 4.9 Rewrap kluczy z poziomu HTTP

#### `POST /api/v1/admin/kms/rewrap`

Wymagane tylko wtedy, gdy flaga `enable_http_rewrap = true` jest włączona.

```bash
curl -X POST http://127.0.0.1:7000/api/v1/admin/kms/rewrap \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: auth-service" \
  -H "X-Timestamp: 2026-08-23T12:00:00Z" \
  -H "X-Nonce: 3b8146cd-d441-4e2d-bb88-04fe0af0cb9a" \
  -H "X-Body-SHA256: <sha256_body>" \
  -H "X-HMAC-Signature: <hmac_hex>" \
  -d '{
    "target_version": 2,
    "batch_size": 100
  }'
```

---

## 5. Limity i timeouty komunikacji

Serwer stosuje ścisłe limity bezpieczeństwa:

- maksymalny rozmiar ramki HSM: `1 MiB` (1048576 bajtów),
- timeout połączenia do HSM: `5 sekund`,
- timeout zapisu do HSM: `5 sekund`,
- timeout odczytu odpowiedzi z HSM: `5 sekund`,
- TTL nonce: `300 sekund` (5 minut),
- okno czasowe timestampu: `±60 sekund` względem czasu serwera.

Jeżeli ramka wejściowa lub odpowiedź przekracza limit rozmiaru, HSM lub klient odpowiada błędem komunikacji i operacja jest odrzucana bez dalszego przetwarzania.

---

## 6. Format błędów i statusy HTTP

W przypadku błędu serwer zwraca strukturę JSON:

```json
{
  "code": "AUTH_FAILED",
  "message": "Autoryzacja nie powiodła się",
  "details": null
}
```

Typowe kody odpowiedzi:

- `200 OK`: poprawne wykonanie żądania,
- `400 Bad Request`: niepoprawne parametry wejściowe lub uszkodzony body,
- `401 Unauthorized`: brak / błąd HMAC, nieprawidłowy lub wygasły timestamp, duplikat nonce,
- `403 Forbidden`: brak uprawnień ACL lub naruszenie polityki dostępu,
- `404 Not Found`: zasób nie istnieje,
- `409 Conflict`: konflikt rotacji / agresywna konkurencja przy aktywnym kluczu,
- `422 Unprocessable Entity`: błąd kryptograficzny / niepoprawna operacja,
- `500 Internal Server Error`: błąd wewnętrzny serwera.

---

## 7. Rekomendacja integracyjna

- Nie używać endpointu eksportu klucza prywatnego; jest niezgodny z polityką KMS.
- Nie cache'ować i nie przekazywać kluczy prywatnych w odpowiedziach HTTP.
- Każde żądanie do KMS powinno generować własny `X-Nonce` i prawidłowo liczyć `X-Body-SHA256`.
- W przypadku opóźnionego, niezsynchronizowanego zegara serwisu klienta, należy skorygować czas lokalny przed wysyłką żądania.

---

## 8. OpenAPI (skrócony szkic)

```yaml
openapi: 3.0.3
info:
  title: KMS Service API
  version: 1.0.0
  description: >-
    KMS service exposes public key, symmetric key, encryption, decryption, signing and rotation
    operations. Private key export is unavailable and never returned over REST.
servers:
  - url: http://127.0.0.1:7000
paths:
  /health:
    get:
      summary: Health check
  /api/v1/keys/generate:
    post:
      summary: Generate a key pair or symmetric key
  /api/v1/keys/public/{service_id}/{algorithm}:
    get:
      summary: Get public key metadata and PKIX material
  /api/v1/keys/rotate:
    post:
      summary: Rotate service key atomically
  /api/v1/keys/symmetric:
    post:
      summary: Get symmetric secret material under ACL policy
  /api/v1/encrypt:
    post:
      summary: Encrypt plaintext using KMS master key
  /api/v1/decrypt:
    post:
      summary: Decrypt ciphertext using KMS master key
  /api/v1/keys/sign:
    post:
      summary: Sign payload with service key without returning private material
  /api/v1/admin/kms/rewrap:
    post:
      summary: Rewrap keys to target master version
components:
  securitySchemes:
    HmacAuth:
      type: apiKey
      in: header
      name: X-HMAC-Signature
      description: >-
        HMAC-SHA256 over METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256
security:
  - HmacAuth: []
```
