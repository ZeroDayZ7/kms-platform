# Instrukcja Obsługi CLI (KMS Service)

Interfejs wiersza poleceń wbudowany w produkcyjną binarkę `kms-service`.

## Dostępne Polecenia

### 1. Uruchomienie Serwera HTTP

Uruchamia produkcyjny serwer REST API.

```bash
./kms-service serve

```

### 2. Bootstrap Zasad / Kluczy Aplikacji

Inicjalizuje w bazie danych MongoDB domyślne reguły ACL oraz wymagane klucze startowe.

```bash
./kms-service bootstrap

```

### 3. Przepakowywanie Kluczy (Master Key Rewrap)

Bezpieczne re-szyfrowanie kluczy w bazie danych do nowszej wersji klucza głównego (Master Key). Zalecana metoda operacyjna zamiast HTTP.

```bash
./kms-service rewrap --target-version 2 --batch-size 100

```

- `--target-version` (wymagane): Docelowa wersja klucza Master Key.
- `--batch-size` (domyślnie 100): Liczba kluczy w pojedynczym wsadzie.

---

### 3. Plik `docs/BOOTSTRAP.md` (Procedura Ceremonii SSSS)

Miejsce na opisienie, jak serwerowy KMS integruje się z wygenerowaną wcześniej ceremonią z repozytorium `kms-ceremony-cli`.

# Procedura Inicjalizacji Ceremonii (Master Key Recovery)

Przewodnik po uruchamianiu serwera KMS z wykorzystaniem odzyskiwania klucza głównego z manifestu ceremonii SSSS.

## Opis Procesu

Serwer KMS wymaga do odszyfrowania swojego klucza magazynu (`storage_key`) podania progu (np. 3 z 5) udziałów wygenerowanych podczas offline'owej ceremonii kluczy (`kms-ceremony-cli`).

## Inicjalizacja z CLI

```bash
./kms-service bootstrap \
  --manifest ./ceremony_manifest.json \
  --shares-dir ./path/to/shares
```

### Przepływ bezpieczny (Zero-Trust):

1. Serwer wczytuje `ceremony_manifest.json` zawierający zaszyfrowany kontener z `storage_key`.
2. Wczytuje udziały z podanego katalogu (`share_1.json`, `share_2.json`, ...).
3. Po zgromadzeniu `threshold` udziałów wywołuje algorytm `ssss::unlock` w celu zrekonstruowania `master_key`.
4. Odszyfrowuje `storage_key` przy użyciu `Aes256Gcm`.
5. Czyści natychmiast `master_key` i bajty pomocnicze z pamięci RAM (`zeroize`).
6. Przechowuje `storage_key` w zabezpieczonym buforze RAM i zmienia stan na `READY`.
