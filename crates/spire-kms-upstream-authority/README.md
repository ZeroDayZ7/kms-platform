# spire-kms-upstream-authority

`spire-kms-upstream-authority` is a lightweight adapter (shim) that integrates **SPIRE Server** with an external **KMS Service** (`kms-service`) via the SPIRE `UpstreamAuthority` plugin interface.

## Purpose

SPIRE Server loads external plugins by spawning sub-processes (`fork/exec`) and communicating over standard gRPC and the HashiCorp `go-plugin` handshake protocol.

Rather than embedding cryptographic logic, database access, or secret key management directly inside a SPIRE plugin, this binary acts as a stateless translation proxy:

1. **Protocol Bridging:** Handles the SPIRE/HashiCorp `go-plugin` sub-process lifecycle and serves the `spire.server.upstreamauthority.v1` gRPC interface.
2. **IPC Forwarding:** Forwards certificate signing requests (`MintX509CA`) over a Unix Domain Socket (UDS) to the standalone `kms-service`.
3. **Security & Isolation:** Keeps the SPIRE Server container isolated from core KMS secrets and database infrastructure.

## Architecture
