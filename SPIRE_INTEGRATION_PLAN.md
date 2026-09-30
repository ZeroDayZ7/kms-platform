# SPIRE Integration Plan for KMS Upstream Authority Shim

## 1. Cel i zakres

Ten dokument definiuje plan wdrożenia lekkiego shima `spire-kms-upstream-authority` w Rust do integracji SPIRE Server z autorskim KMS (`kms-service`).

Shim ma pełnić wyłącznie rolę proxy / adaptera:

- jest uruchamiany przez SPIRE jako zewnętrzny plugin,
- przyjmuje żądania zgodne z protokołem SPIRE UpstreamAuthority v1,
- przekazuje je do lokalnego `kms-service` po stronie KMS przez Unix Domain Socket,
- zwraca wynik zgodny z oczekiwaniami SPIRE.

W tej fazie dokument ma charakter specyfikacji technicznej i planu akceptacyjnego. Nie wprowadza zmian w konfiguracji runtime ani w kodzie produkcyjnym repozytorium.

---

## 2. Stan obecny w repozytorium

### 2.1. Konfiguracja SPIRE Server

W repozytorium `kms-infra` obecnie występuje konfiguracja:

```hcl
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/run/spire/data/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/run/spire/data/keys.json"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    UpstreamAuthority "kms_plugin" {
        plugin_cmd = "/opt/spire/bin/spire-kms-upstream-authority"
        plugin_checksum = ""
        plugin_data {
            kms_grpc_socket = "/run/kms/kms.sock"
            ca_tag = "root"
        }
    }
}
```

To oznacza, że:

- SPIRE Server jest zaprojektowany do załadowania zewnętrznego pluginu pod ścieżką `/opt/spire/bin/spire-kms-upstream-authority`,
- plugin ma otrzymać ustawienia:
  - `kms_grpc_socket = "/run/kms/kms.sock"`
  - `ca_tag = "root"`
- obecny problem polega na tym, że plik wykonywalny nie jest dostępny w kontenerze `spire-server` i komenda `plugin_cmd` nie może wykonać binarki.

### 2.2. Istniejące elementy w `kms-platform`

W repozytorium `kms-platform` istnieje już część kontraktu SPIRE UpstreamAuthority:

- `crates/kms-service/proto/spire/server/upstreamauthority/v1/upstreamauthority.proto`
- `crates/kms-service/src/grpc/upstream_authority.rs`

To potwierdza, że domena `MintX509CA` jest już rozpoznawana i ma mapowanie do `kms-service`.

Obecnie w repo nie ma jednak osobnego binarnego shima SPIRE, który:

- byłby uruchamiany przez SPIRE jako plugin,
- obsługiwał handshake go-plugin,
- ekspował gRPC `spire.server.upstreamauthority.v1`,
- proxyował zapytania przez UDS do `kms-service` bez dostępu do bazy danych.

---

## 3. Wymagany kontrakt SPIRE UpstreamAuthority v1

### 3.1. Wersja minimalna obecnie potrzebna

W repo już istnieje minimalny kontrakt:

```proto
syntax = "proto3";

package spire.server.upstreamauthority.v1;

service UpstreamAuthority {
  rpc MintX509CA(MintX509CARequest) returns (MintX509CAResponse);
}

message MintX509CARequest {
  string csr_pem = 1;
  string ca_tag = 2;
}

message MintX509CAResponse {
  repeated string x509_ca_chain = 1;
}
```

To jest kontrakt wystarczający do podpisania CSR przez KMS i zwrócenia łańcucha certyfikatów do SPIRE Server.

### 3.2. Rozszerzenie dla przyszłej obsługi JWT / PublishJWTKey

W modelu SPIRE UpstreamAuthority istnieje również potrzeba obsługi JWT: `PublishJWTKey`. W praktyce planowane wdrożenie powinno obejmować także tę operację jako przyszłe rozszerzenie, ponieważ SPIRE nierzadko używa dwóch typów upstream authority:

- `MintX509CA` dla certyfikatów X.509,
- `PublishJWTKey` dla kluczy JWT / JWKS.

Proponowany kontrakt rozwojowy:

```proto
syntax = "proto3";

package spire.server.upstreamauthority.v1;

service UpstreamAuthority {
  rpc MintX509CA(MintX509CARequest) returns (MintX509CAResponse);
  rpc PublishJWTKey(PublishJWTKeyRequest) returns (PublishJWTKeyResponse);
}

message MintX509CARequest {
  string csr_pem = 1;
  string ca_tag = 2;
}

message MintX509CAResponse {
  repeated string x509_ca_chain = 1;
}

message PublishJWTKeyRequest {
  string key_id = 1;
  string public_jwk_pem = 2;
  string ca_tag = 3;
}

message PublishJWTKeyResponse {
  bool ok = 1;
}
```

W fazie minimalnej integracji `MintX509CA` jest warunkiem koniecznym i wystarczającym. `PublishJWTKey` należy traktować jako ścieżkę rozszerzenia, z zachowaniem zero-business-logic w samym pluginie.

---

## 4. Architektura docelowa shima

### 4.1. Rola shima

Shim `spire-kms-upstream-authority` ma być:

- wykonywalnym binarnym pluginem dla SPIRE Server,
- lekkim adapterem gRPC / proxy,
- warstwą transformacji pomiędzy protokołem SPIRE i lokalnym gRPC `kms-service`.

Nie może on:

- zawierać logiki biznesowej KMS,
- wykonywać operacji kryptograficznych samodzielnie,
- mieć dostępu bezpośredniego do bazy danych,
- przechowywać kluczy i certyfikatów poza lokalnym `kms-service`.

### 4.2. Struktura crate'a

Proponowana struktura nowego crate'a w monorepo `kms-platform`:

```text
crates/
  spire-kms-upstream-authority/
    Cargo.toml
    build.rs
    src/
      main.rs
      config.rs
      handshake.rs
      grpc_server.rs
      kms_client.rs
      proxy.rs
      proto/
        mod.rs
```

Zasada organizacyjna:

- `main.rs` = punkt wejścia binarki pluginu,
- `handshake.rs` = obsługa standardowego handshake `go-plugin` / SPIRE plugin bootstrap,
- `grpc_server.rs` = gRPC service for `spire.server.upstreamauthority.v1`,
- `kms_client.rs` = klient do `kms-service` przez UDS,
- `proxy.rs` = transformacja żądania SPIRE -> żądanie KMS -> odpowiedź KMS -> odpowiedź SPIRE,
- `config.rs` = odczyt ustawień z `plugin_data` / env / args.

### 4.3. UDS do `kms-service`

Docelowy kontrakt komunikacji lokalnej:

- adres: `/run/kms/kms.sock`
- rodzaj: Unix Domain Socket,
- protokół: gRPC lub prosty lokalny RPC wewnętrzny, zależnie od tego, która ścieżka będzie ostatecznie przyjęta w `kms-service`,
- kierunek: shim -> `kms-service`.

Wartości przekazywane z plugin_data:

- `kms_grpc_socket` = `/run/kms/kms.sock`
- `ca_tag` = `root`

W praktyce shim odczytuje te wartości i używa ich do konfiguracji połączenia oraz domyślnej polityki wyboru CA upstream.

---

## 5. Mechanizm handshake i gRPC SPIRE

### 5.1. Wymaganie pluginu go-plugin

SPIRE używa modelu pluginów w stylu HashiCorp go-plugin. Oznacza to, że exe pluginu jest uruchamiany przez host (SPIRE Server) i musi komunikować się zgodnie z handshake protokołem zdefiniowanym przez go-plugin.

W praktyce plugin musi:

1. rozpocząć działanie jako proces wykonywalny,
2. przejść przez standardowy handshake na kanale `stdin/stdout`,
3. uruchomić gRPC server dla SPIRE `UpstreamAuthority` service,
4. odpowiadać na żądania weryfikacji i podpisania certyfikatów.

Warto podkreślić, że plugin nie musi implementować własnej logiki podpisywania certyfikatu; jego jedynym zadaniem jest przekazanie wywołania do `kms-service` i zwrócenie odpowiedzi.

### 5.2. Różnica między SPIRE plugin i `kms-service`

- `SPIRE Server` rozmawia z pluginem przez protokół plugin-host,
- plugin rozmawia z `kms-service` przez UDS / zwykły gRPC,
- `kms-service` wykonuje właściwe operacje kryptograficzne i zapisywanie do bazy danych,
- shim nie jest źródłem prawdy kryptograficznej ani stanu systemu.

### 5.3. Typowy flow request/reply

1. SPIRE Server wywołuje plugin z konfiguracji `plugin_cmd`.
2. Plugin przechodzi handshake i aktywuje endpoint gRPC.
3. SPIRE wysyła żądanie `MintX509CA` z parametrami:
   - `csr_pem`
   - `ca_tag`
4. Shim mapuje żądanie do wewnętrznego wywołania do `kms-service` przez UDS.
5. `kms-service` wykonuje istniejącą logikę `SignIntermediateCaUseCase` / `RootCaQueries`.
6. `kms-service` zwraca `x509_ca_chain`.
7. Shim przesyła wynik do SPIRE Server.

### 5.4. Mapowanie żądań

Mapowanie jest następujące:

```text
SPIRE: MintX509CARequest {
  csr_pem,
  ca_tag
}

--> shim --> kms-service (gRPC/UDS)

KMS: SignIntermediateCaInput {
  caller_service: "spire",
  ca_tag: ca_tag,
  csr_pem: csr_pem,
  validity_days: 3650
}

--> kms-service logic --> certificate chain

SPIRE: MintX509CAResponse {
  x509_ca_chain: [intermediate_cert, root_cert]
}
```

To mapowanie jest zgodne z istniejącym kodem w `crates/kms-service/src/grpc/upstream_authority.rs` i `SignIntermediateCaUseCase`.

---

## 6. Wyzwania bezpieczeństwa i ograniczenia

### 6.1. Tylko proxy

Shim musi:

- być bezstanowy względem danych kryptograficznych,
- nie przechowywać certyfikatów / kluczy / haseł,
- przekazywać wszystkie requesty do `kms-service`,
- nie używać bazy danych lokalnie.

### 6.2. Własne sockety i uprawnienia

Docelowe środowisko powinno zapewniać:

- utworzenie katalogu `/run/kms`
- ownership / perms dla UDS
- wskazanie pluginowi ścieżki socketu w konfiguracji `plugin_data`
- odpowiednie flagi bezpieczeństwa dla kontenera `spire-server` i hosta K8s

### 6.3. Dodatkowe ochrony

- włączone ACL / authn dla lokalnego gRPC z `kms-service`,
- ograniczony zakres `ca_tag`,
- weryfikacja `csr_pem` i logowanie tylko bezpiecznych metadanych,
- brak ekspozycji wewnątrz shima sensytywnych danych z DB.

---

## 7. Struktura protokołu i zależności Rust

### 7.1. Dodatkowe zależności Cargo (planowane)

Docelowo nowe `Cargo.toml` dla crate'a powinno zawierać co najmniej:

```toml
[dependencies]
anyhow = "1"
tokio = { version = "1", features = ["full"] }
tonic = { version = "0.13", features = ["prost"] }
prost = "0.13"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
```

W zależności od wyboru implementacji można dodać:

- `tower`,
- `tonic-reflection` (opcjonalnie),
- `hyperlocal` / `tokio-stream` dla UDS,
- `thiserror`.

### 7.2. Generacja kodu z `.proto`

Dla `MintX509CA` i ewentualnego `PublishJWTKey` można użyć `tonic-build` albo `prost-build`.

```rust
tonic_build::configure()
    .build_server(true)
    .compile(&["proto/spire/server/upstreamauthority/v1/upstreamauthority.proto"], &["proto"])?;
```

W praktyce:

- `proto` jest źródłem definicji kontraktu,
- `tonic` wygeneruje serwer i klienta Rust,
- plugin implikuje `UpstreamAuthority` service,
- `kms-service` może też używać wygenerowanego kodu dla kompatybilności.

---

## 8. Wersja Docker / K3s docelowa

### 8.1. Wymagane montowanie binarki do `spire-server`

W kontenerze SPIRE Server musi istnieć plik:

```text
/opt/spire/bin/spire-kms-upstream-authority
```

Zabezpieczenie wykonawcze:

```bash
chmod +x /opt/spire/bin/spire-kms-upstream-authority
```

### 8.2. Wzór konfiguracji Docker Compose

Docelowo konfiguracja dla `spire-server` powinna dawać możliwość dopinania binarki z obrazu build-stage lub z wolumenu podzielonego z projektem Rust:

```yaml
services:
  spire-server:
    image: ghcr.io/spiffe/spire-server:1.11.1
    volumes:
      - ./spire/server:/opt/spire/conf/server:ro
      - ./bin/spire-kms-upstream-authority:/opt/spire/bin/spire-kms-upstream-authority:ro
      - /run/kms:/run/kms
      - spire-server-data:/run/spire/data
      - spire-server-socket:/tmp/spire-server/private
    command:
      - "/opt/spire/bin/spire-server"
      - "run"
      - "-config"
      - "/opt/spire/conf/server/server.conf"
    entrypoint:
      - /bin/sh
      - -c
      - |
        chmod +x /opt/spire/bin/spire-kms-upstream-authority
        exec /opt/spire/bin/spire-server run -config /opt/spire/conf/server/server.conf
```

Konieczne jest też wskazanie wolumenu `/run/kms` do wspólnego socketu UDS:

```yaml
volumes:
  - /run/kms:/run/kms
```

### 8.3. Wzór konfiguracji K3s / Deployment

W K3s / Kubernetes rekomendowana jest konfiguracja typu:

- `ConfigMap` na `server.conf`,
- `emptyDir` albo `hostPath` dla `/run/kms`,
- `initContainer` budujący plugin w obrazie Rust,
- dodatkowy `volumeMount` do `/opt/spire/bin`.

Przykładowy koncept:

```yaml
spec:
  containers:
    - name: spire-server
      image: ghcr.io/spiffe/spire-server:1.11.1
      volumeMounts:
        - name: spire-config
          mountPath: /opt/spire/conf/server
          readOnly: true
        - name: spire-plugin-bin
          mountPath: /opt/spire/bin
        - name: kms-uds
          mountPath: /run/kms
  initContainers:
    - name: prepare-spire-plugin
      image: rust:1.80
      command:
        - /bin/sh
        - -c
        - |
          mkdir -p /opt/spire/bin /run/kms
          cp /workspace/target/release/spire-kms-upstream-authority /opt/spire/bin/spire-kms-upstream-authority
          chmod +x /opt/spire/bin/spire-kms-upstream-authority
      volumeMounts:
        - name: spire-plugin-bin
          mountPath: /opt/spire/bin
```

W praktyce finalne wdrożenie można zrealizować przez:

- multi-stage Docker build z narzędziem Rust,
- kopiowanie binarki do wybranego katalogu w obrazie `spire-server`,
- albo przez wspólny wolumen między builderem a runtime.

---

## 9. Mapa integracji z `kms-service`

### 9.1. Istniejący backend

Repo już dostarcza backend do podpisywania pośredniego certyfikatu:

- `crates/kms-service/src/grpc/upstream_authority.rs`
- `crates/kms-service/src/application/use_cases/sign_intermediate_ca.rs`

System działa w ten sposób:

- przyjmuje `csr_pem`,
- wybiera odpowiednią CA (`ca_tag`),
- podpisuje ją przez `kms-service`,
- zwraca `x509_ca_chain` z certyfikatem pośrednim i certyfikatem root.

### 9.2. Rola shima

Shim musi tylko zmapować wywołanie SPIRE do tego istniejącego endpointu KMS. Oznacza to, że:

- nie należy implementować nowej symetrii podpisywania certyfikatu w pluginie,
- nie należy dodawać biznesowej logiki do pluginu,
- należy zachować `kms-service` jako jedyne miejsce, w którym dzieje się generowanie, podpisywanie i zapis stanu bezpieczeństwa.

### 9.3. Wewnętrzny kontrakt do KMS

Wersja planowana:

```rust
pub struct SignIntermediateCaInput {
    pub caller_service: ServiceId,
    pub ca_tag: String,
    pub csr_pem: String,
    pub validity_days: u32,
}
```

I odpowiedź:

```rust
pub struct SignIntermediateCaOutput {
    pub certificate_pem: String,
    pub ca_chain: Vec<String>,
}
```

Shim ma być jedynie lokalnym klientem gRPC UDS do `kms-service`. Wewnętrzny kontekst bezpieczeństwa (`caller_service = "spire"`) jest zdefiniowany na poziomie shima, a nie przez sam SPIRE.

---

## 10. Plan implementacji w kolejnych etapach

### Etap A — kontrakt i bundle plugin

- utworzyć nowy crate `spire-kms-upstream-authority`,
- dodać `Cargo.toml` i `proto` definitions,
- wygenerować Rust bindings dla `spire.server.upstreamauthority.v1`.

### Etap B — plugin handshake

- zaimplementować standardowy startup handshake,
- zapewnić ścieżkę `stdin/stdout` zgodną z modelem `go-plugin` dla SPIRE,
- uruchomić gRPC service w procesie pluginu.

### Etap C — adapter do KMS

- połączyć shim z `kms-service` po UDS,
- zmapować widok `MintX509CARequest` do `SignIntermediateCaInput`,
- zwrócić wynik do SPIRE.

### Etap D — runtime deployment

- dodać montowanie binarki do `spire-server`,
- zainicjalizować katalog `/run/kms`,
- dodać `chmod +x` na binarkę,
- uruchomić `spire-server` i sprawdzić zdrowie.

### Etap E — walidacja integracji

- sprawdzić, czy `spire-server` ładuje plugin bez błędu `fork/exec ... no such file or directory`,
- sprawdzić `spire-agent` i pobieranie SVID,
- zweryfikować, że `kms-service` wykonuje podpisanie CA w reakcji na żądanie `MintX509CA`.

---

## 11. Kryteria akceptacji

Integracja jest uznana za poprawną, gdy:

1. SPIRE Server uruchamia plugin pod `plugin_cmd = "/opt/spire/bin/spire-kms-upstream-authority"` bez błędu `fork/exec`.
2. Plugin przechodzi handshake go-plugin i rejestruje `UpstreamAuthority` v1 service.
3. SPIRE Server może wywołać `MintX509CA` z CSR i otrzymać łańcuch certyfikatów.
4. Shim nie wykonuje logiki biznesowej KMS, tylko proxy do `kms-service` przez UDS.
5. `kms-service` pozostaje jedynym punktem wdrożenia polityki bezpieczeństwa, podpisywania i kontroli kluczy.
6. W środowiskach Docker Compose / K3s plugin jest dostępny pod poprawną ścieżką i ma uprawnienia wykonawcze.

---

## 12. Wniosek

Obecny problem nie wynika z błędu SPIRE ani z niezgodności protokołu w repozytorium. Jest to problem infrastrukturalny i wdrożeniowy: wewnątrz kontenera SPIRE brakuje binarki pluginu, mimo że konfiguracja `server.conf` wskazuje na poprawny punkt wejścia i poprawne `plugin_data`.

Najważniejsze dla kolejnego etapu jest zachowanie zasady: `spire-kms-upstream-authority` ma być cienkim adapterem, a nie własnym KMS. Integracja po stronie SPIRE powinna zostać zrealizowana w sposób zgodny z modelem `go-plugin` i prostym gRPC `UpstreamAuthority` v1, z komunikacją do `kms-service` przez UDS.
