# Instrukcja Wdrożenia i Inicjalizacji KMS (Bootstrap Runbook)

Dokument opisuje krok po kroku procedurę bezpiecznego tworzenia kluczy, ich transferu oraz uruchamiania usługi Key Management Service (KMS).

---

## Przegląd Procesu

```text
[ 1. AIR-GAPPED CLI ] ──> [ 2. TRANSFER ] ──> [ 3. KMS BOOTSTRAP ] ──> [ 4. SERVE API ]
 (kms-ceremony-cli)     (Only Manifest)       (kms-service)          (In-Memory Active)

```

---

## Krok 1: Generowanie Ceremonii (Środowisko Odizolowane / Air-Gapped)

Prace należy wykonać na stacji odłączonej od sieci lokalnej i Internetu.

1. Uruchomienie narzędzia ceremonii z podaniem liczby udziałów ($N$) oraz progu odzyskania ($T$):

```bash
kms-ceremony-cli generate --shares 5 --threshold 3 --output-dir ./out

```

2. Weryfikacja wygenerowanych artefaktów w katalogu `./out`:

- `ceremony_manifest.json` – zaszyfrowany kontener zawierający klucz magazynu (`storage_key`).
- `shares/share_1.json` ... `shares/share_5.json` – indywidualne udziały Shamira (SSSS).

3. Dystrybucja udziałów:

- Każdy plik `share_X.json` należy przekazać osobnemu Strażnikowi Klucza na zabezpieczonym nośniku.
- Usunięcie udziałów ze stacji generującej po potwierdzeniu przekazania.

---

## Krok 2: Transfer Manifestu na Środowisko Docelowe

1. Przeniesienie **wyłącznie** pliku `ceremony_manifest.json` na serwer produkcyjny lub wolumen klastra.
2. **Kategoryczny zakaz** wgrywania plików udziałów `share_X.json` na stały dysk serwera produkcyjnego.

---

## Krok 3: Inicjalizacja Usługi (Bootstrap)

Inicjalizacja wymaga fizycznej lub bezpiecznej obecności co najmniej wymaganej liczby Strażników Kluczy ($T$).

1. Zebranie wymaganej liczby plików udziałów (np. 3 z 5) w tymczasowym katalogu `./shares`.
2. Wykonanie komendy inicjalizującej zablokowany stan KMS:

```bash
kms-service bootstrap \
  --manifest ./ceremony_manifest.json \
  --shares-dir ./shares

```

3. Automatyczny przebieg operacji w pamięci RAM:

- Odczyt udziałów i rekonstrukcja klucza głównego (`master_key`).
- Odszyfrowanie `storage_key` z manifestu.
- Natychmiastowe czyszczenie `master_key` z pamięci procesora (`zeroize`).
- Zapis `storage_key` w zabezpieczonym buforze RAM i przejście usługi w stan `READY`.

4. Bezpieczne usunięcie tymczasowego katalogu `./shares` z serwera po zakończeniu procedury.

---

## Krok 4: Uruchomienie Usługi HTTP API

Po pomyślnym wykonaniu kroku bootstrapu następuje uruchomienie produkcyjnego serwera HTTP:

```bash
kms-service serve

```
