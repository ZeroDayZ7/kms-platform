# KMS Ceremony CLI

Narzędzie CLI w Rust służące do przeprowadzania ceremonii kluczy oraz odblokowywania (unseal) usługi `vhsm-daemon` przy użyciu schematu Shamir's Secret Sharing (SSS).

---

## Główne Funkcje

- **Interaktywna Ceremonia (Interactive):** Zleca `vhsm-daemon` wygenerowanie nowego Master Key, odbiera udziały SSS i szyfruje każdy z nich wybranym hasłem/PIN-em Oficera (Argon2 + AES-GCM).
- **Odblokowanie vHSM (Unseal):** Odtwarza Master Key w pamięci RAM daemona na podstawie wczytanych i odszyfrowanych udziałów SSS.
- **Dedykowana Walidacja Bezpieczeństwa:** Weryfikuje unikalność indeksów Oficerów (Fast Fail UX) przed wysłaniem zapytania do socketa IPC.
- **Zeroizacja:** Wszystkie klucze i sekrety w pamięci CLI są automatycznie czyszczone przy zwolnieniu pamięci (`Zeroize on Drop`).

---

## Komendy

### 1. Interaktywna Ceremonia Klucza (`interactive`)

Inicjalizuje `vhsm-daemon`, generuje Master Key w pamięci RAM daemona i zapisuje zaszyfrowane udziały dla Oficerów.

```bash
kms-ceremony-cli interactive --shares 5 --threshold 3 --output-dir ./out

```

**Uruchomienie w Dockerze:**

```bash
MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli interactive --socket-path /run/vhsm/vhsm.sock

```

**Opcje:**

- `-s, --shares <N>`: Liczba wszystkich udziałów (domyślnie: `5`).
- `-t, --threshold <T>`: Próg udziałów wymagany do odblokowania (domyślnie: `3`).
- `-o, --output-dir <DIR>`: Katalog wyjściowy dla plików udziałów (domyślnie: `./out`).
- `--socket-path <PATH>`: Ścieżka do gniazda UNIX vHSM (domyślnie: `/run/vhsm/vhsm.sock`).

**Struktura plików wyjściowych:**

```text
out/
└── shares/
    ├── share_1.json
    ├── share_2.json
    └── ...

```

---

### 2. Odblokowanie vHSM (`unseal`)

Ładuje zaszyfrowane pliki udziałów z katalogu, prosi o hasła Oficerów i wysyła odszyfrowane udziały do `vhsm-daemon`.

```bash
kms-ceremony-cli unseal --threshold 3 --shares-dir ./out/shares

```

**Opcje:**

- `-t, --threshold <T>`: Wymagany próg udziałów (domyślnie: `3`).
- `-d, --shares-dir <DIR>`: Katalog zawierający pliki `share_X.json`.
- `--socket-path <PATH>`: Ścieżka do gniazda UNIX vHSM (domyślnie: `/run/vhsm/vhsm.sock`).

---

### 3. Ręczne Inicjalizowanie Klucza (`init-master-key`)

Podanie udziałów bezpośrednio w formacie `INDEX:HEX` przez argumenty CLI:

```bash
kms-ceremony-cli init-master-key --threshold 3 "1:a3f5..." "2:b8c9..." "3:d1e2..."

```

---

## Struktura Pliku Udziału (`share_X.json`)

KONTENER ZASZYFROWANEGO UDZIAŁU OFICERA:

```json
{
  "index": 1,
  "threshold": 3,
  "total_shares": 5,
  "share_hex": "{\"nonce\":\"...\",\"ciphertext\":\"...\",\"kdf_salt\":\"...\"}",
  "share_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "created_at": "2026-08-20T16:00:00Z"
}
```
