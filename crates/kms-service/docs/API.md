# Specyfikacja API HTTP (KMS Service)

Dokumentacja interfejsu REST API usługi Key Management Service (KMS) przeznaczona dla mikroserwisów klienckich.

---

## Adres Bazowy (Base URL)

- **Development:** `http://127.0.0.1:7000`
- **Docker / Production:** `http://kms-service.internal:8080`

---

## Autoryzacja HMAC-SHA256

Wszystkie chronione endpointy wymagają nagłówków:

- `X-Service-Name` – identyfikator wywołującego (np. `auth-service`)
- `X-Timestamp` – stempel Unix w sekundach
- `X-HMAC-Signature` – podpis hex: `HMAC-SHA256(SECRET, "METHOD:PATH:TIMESTAMP")`

---

## Endpointy API

### 1. Health Check

`GET /health` (Brak HMAC)

### 2. Generowanie Klucza

`POST /api/v1/keys/generate`

### 3. Pobieranie Klucza Publicznego

`GET /api/v1/keys/public/{service_id}/{algorithm}`

### 4. Pobieranie Klucza Prywatnego

`POST /api/v1/keys/private`

### 5. Pobieranie Klucza Symetrycznego

`POST /api/v1/keys/symmetric`

### 6. Rotacja Klucza

`POST /api/v1/keys/rotate`

### 7. Szyfrowanie Kopertowe

`POST /api/v1/encrypt`

### 8. Odszyfrowanie Kopertowe

`POST /api/v1/decrypt`

### 9. Zdalne Podpisywanie Danych / JWT

`POST /api/v1/keys/sign`

### 10. Przepakowanie Kluczy Admina (HTTP Rewrap)

`POST /api/v1/admin/kms/rewrap` _(Wymaga `enable_http_rewrap = true`)_
