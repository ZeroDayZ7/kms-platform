```text
[ 1. AIR-GAPPED CLI ] ──> [ 2. TRANSFER ] ──> [ 3. KMS BOOTSTRAP ] ──> [ 4. SERVE API ]
 (kms-ceremony-cli)     (Only Manifest)       (kms-service)          (In-Memory Active)

```

---

### Pełny przepływ krok po kroku

#### Krok 1: Generowanie Ceremonii (Stacja Offline / Air-Gapped)

1. Uruchamiasz `kms-ceremony-cli generate --shares 5 --threshold 3 --output-dir ./out`.
2. Narzędzie generuje:

- **`ceremony_manifest.json`** – zaszyfrowany kontener z `storage_key`.
- **`shares/share_1.json ... share_5.json`** – udziały SSSS dla Strażników Kluczy.

3. Pliki `share_X.json` trafiają do odpowiednich osób/Strażników na bezpiecznych nośnikach.

#### Krok 2: Transfer Manifestu na Środowisko Produkcyjne

1. Administrator przenosi **wyłącznie** plik `ceremony_manifest.json` na serwer produkcyjny (lub do wolumenu K8s).
2. Udziały `share_X.json` **nigdy nie są zapisywane na stałe na serwerze**.

#### Krok 3: Bootstrap i Odzyskanie Klucza (Start KMS)

1. Podczas wdrażania/startu serwera podajesz manifest oraz minimum $T$ udziałów (np. 3 zebrane od Strażników):

```bash
./kms-service bootstrap --manifest ./ceremony_manifest.json --shares-dir ./shares

```

2. KMS:

- Odczytuje udziały i składa z nich `master_key` w pamięci RAM.
- Odszyfrowuje `storage_key` z manifestu.
- Natychmiast czyści `master_key` z pamięci (`zeroize`).
- Zapisuje `storage_key` w zabezpieczonym buforze RAM i ustawia stan usługi na `READY`.

#### Krok 4: Uruchomienie Serwera HTTP / API

1. Serwer startuje z gotowym, odblokowanym buforem w pamięci RAM:

```bash
./kms-service serve

```

2. Mikroserwisy klienckie (np. `auth-service`) mogą zacząć odpytywać API HTTP o klucze, szyfrowanie kopertowe i podpisywanie danych HMAC/JWT.

---
