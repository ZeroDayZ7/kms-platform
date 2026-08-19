# KMS Ceremony CLI

Aplikacja CLI (Command-Line Interface) napisana w języku Rust, przeznaczona do prowadzenia oficjalnych ceremonii zarządzania kluczami (KMS - Key Management Service) w środowisku offline. Narzędzie umożliwia generowanie kryptograficznych kluczy głównych (Master Key) oraz magazynu (Storage Key), ich podział przy użyciu schematu podziału sekretu Shamira (SSSS), a także późniejsze odzyskiwanie kluczy z aktywnych udziałów.

---

## Funkcjonalności

- **Shamir's Secret Sharing (SSSS)**: Podział klucza głównego na określoną liczbę udziałów ($N$) z wyznaczonym progiem odzyskania ($T$).

- **Szyfrowanie AES-256-GCM**: Bezpieczne konteneryzowane szyfrowanie kluczy magazynu przy użyciu kluczy głównych.

- **Manifest Audytowy Ceremonii**: Automatyczne generowanie struktury JSON zawierającej metadane, wartości nonce oraz zaszyfrowany ciąg ciphertext.

- **Tryb Interaktywny**: Krok po kroku prowadzący użytkownika przez proces generowania i odzyskiwania kluczy w terminalu.

- **Czyszczenie Pamięci (Zeroization)**: Bufory pamięci zawierające klucze kryptograficzne są automatycznie zerowane (zeroized) przy niszczeniu obiektów.

---

## Składnia Poleceń

```text
kms-ceremony-cli [SUBKOMENDA] [OPCJE]

```

### Dostępne Subkomendy

- `generate`: Generuje klucz główny, klucz magazynu, udziały SSSS oraz manifest ceremonii.

- `recover`: Odtwarza klucz główny na podstawie katalogu zawierającego prawidłowe pliki JSON z udziałami.

- `interactive`: Uruchamia interaktywny kreator w terminalu.

---

## Instrukcja Użycia

### 1. Generowanie Kluczy i Udziałów

Aby wygenerować klucz podzielony na 5 udziałów z progiem odzyskania równym 3:

```bash
kms-ceremony-cli generate --shares 5 --threshold 3 --output-dir ./out

```

**Opcje**:

- `-s, --shares <LICZBA>`: Całkowita liczba udziałów SSSS do wygenerowania (domyślnie: `5`).

- `-t, --threshold <LICZBA>`: Minimalna liczba udziałów wymagana do odzyskania klucza (domyślnie: `3`).

- `-o, --output-dir <KATALOG>`: Ścieżka katalogu wyjściowego dla manifestu i udziałów (domyślnie: `./out`).

**Struktura Wyjściowa Katalogu**:

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

### 2. Odzyskiwanie Klucza Głównego

Aby odtworzyć oryginalny klucz główny, wskaż katalog zawierający co najmniej $T$ prawidłowych plików JSON z udziałami:

```bash
kms-ceremony-cli recover --shares-dir ./out/shares --output-key ./recovered.key

```

**Opcje**:

- `-d, --shares-dir <KATALOG>`: Katalog zawierający pliki JSON z udziałami (domyślnie: `./out/shares`).

- `-k, --output-key <PLIK>`: Ścieżka do pliku wyjściowego dla odzyskanego klucza w formacie hex (domyślnie: `./recovered.key`).

---

### 3. Tryb Interaktywny

Uruchomienie interaktywnego kreatora w terminalu:

```bash
kms-ceremony-cli

```

LUB bezpośrednie wywołanie subkomendy:

```bash
kms-ceremony-cli interactive --output-dir ./out

```

---

## Struktury Plików

### Manifest Ceremonii (`ceremony_manifest.json`)

Zawiera metadane ceremonii, parametry progu, listę wygenerowanych plików oraz zaszyfrowany kontener klucza magazynu:

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

### Plik Udziału (`share_X.json`)

Zawiera pojedynczy udział wraz z sumą kontrolną SHA-256:

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
