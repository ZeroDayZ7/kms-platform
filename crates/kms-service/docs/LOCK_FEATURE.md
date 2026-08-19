# KMS Lock Feature Documentation

## Overview

The **KMS Lock feature** provides two mechanisms to secure the Key Management Service by clearing the master key from memory:

1. **HTTP API Lock Endpoint** – Optional, disabled by default
2. **CLI Lock Command** – Local OS-level, no authorization required

## Configuration

### 1. Enable/Disable HTTP Lock Endpoint

Add to your configuration:

**`config/settings.toml`:**

```toml
[crypto]
enable_http_lock = false  # Set to true to enable HTTP lock endpoint
```

**Environment Variable:**

```bash
export CRYPTO__ENABLE_HTTP_LOCK=true
```

**Default:** `false` (for security; endpoint is 404 when disabled)

### 2. Authorization

- **HTTP Lock Endpoint**: Requires HMAC authentication (same as other admin endpoints)
- **CLI Lock Command**: No authorization required (relies on OS process permissions)

---

## Usage

### Option A: CLI Lock (Recommended for Local/Container Environments)

#### Direct CLI Command

```bash
# Inside container or with binary in PATH
kms-service lock
```

#### Using Script

```bash
./scripts/lock.sh
```

**Output:**

```
🔒 Locking KMS: clearing master key from memory...
✅ KMS successfully locked.
```

**Status after lock:**

- `GET /status` returns `{"status":"LOCKED","manifest_loaded":true}`
- All business endpoints return `HTTP 503: KMS_LOCKED`
- `/health`, `/status`, `/api/v1/admin/ceremony/unlock` remain available

### Option B: HTTP Lock Endpoint (If Enabled)

**Prerequisites:**

- `CRYPTO__ENABLE_HTTP_LOCK=true` in configuration
- Valid HMAC authentication

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/admin/ceremony/lock \
  -H "Content-Type: application/json" \
  -H "Authorization: Hmac service_id=KMS_CLI timestamp=<TS> signature=<SIG>"
```

**Response (Success):**

```json
{
  "status": "LOCKED"
}
```

**Response (Endpoint Disabled):**

```
HTTP 404 Not Found
```

---

## Behavior After Lock

### 1. KMS State

- Internal storage key is **cleared from memory** (`Arc<RwLock<Option<T>>>` → `None`)
- Atomic flag `kms_unlocked` set to `false`
- Zeroization is automatic (via `SecureStorageKey` with `#[derive(ZeroizeOnDrop)]`)

### 2. Endpoint Access

| Endpoint                      | Status                          | Response                                     |
| ----------------------------- | ------------------------------- | -------------------------------------------- |
| `GET /health`                 | 200 OK                          | Shows KMS status                             |
| `GET /status`                 | 200 OK                          | `{"status":"LOCKED","manifest_loaded":true}` |
| `POST /admin/ceremony/unlock` | 200 OK                          | Accepts shares to re-unlock                  |
| `POST /admin/ceremony/lock`   | 404 (disabled) or 200 (enabled) | Lock confirms                                |
| `POST /api/v1/encrypt`        | 503                             | KMS_LOCKED error                             |
| `POST /api/v1/decrypt`        | 503                             | KMS_LOCKED error                             |
| `POST /api/v1/keys/*`         | 503                             | KMS_LOCKED error                             |

### 3. Recovery

To restore functionality after lock:

```bash
# Call unlock with shares
curl -X POST http://localhost:8080/api/v1/admin/ceremony/unlock \
  -H "Content-Type: application/json" \
  -H "Authorization: Hmac ..." \
  -d '{"shares":["share_hex_1","share_hex_2","share_hex_3"]}'
```

---

## Security Considerations

### CLI Lock

- ✅ No network exposure
- ✅ Protected by OS-level process permissions
- ✅ Suitable for containerized environments (e.g., `docker exec`)
- ✅ Can be triggered via signals or orchestration tools

### HTTP Lock Endpoint

- ⚠️ Network-exposed (if enabled)
- ✅ Requires HMAC authentication
- ⚠️ Enable only if you have trusted admin clients
- ⚠️ Monitor and log all lock attempts

### Best Practice

- Keep `enable_http_lock = false` in production
- Use CLI lock via local container/process access
- Reserve HTTP lock for development/testing environments

---

## Implementation Details

### Code Locations

**Configuration:**

- `src/config/crypto.rs` – `CryptoSettings::enable_http_lock`

**Handlers:**

- `src/handlers/admin.rs` – `lock_handler` (HTTP) & `unlock_handler` (HTTP)

**Routes:**

- `src/server/routes.rs` – Conditional registration of lock endpoint

**CLI:**

- `src/main.rs` – `Command::Lock` variant

**State Management:**

- `src/server/state.rs` – `clear_storage_key()` & `is_unlocked()` atomics

### Zeroization Guarantee

```rust
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureStorageKey([u8; 32]);
```

When the Arc is dropped (after `clear_storage_key`), the entire 32-byte key is securely wiped from memory.

---

## Testing

### Test Lock Behavior

```bash
# 1. Check initial status (assuming locked by default)
curl http://localhost:8080/status
# {"status":"LOCKED","manifest_loaded":true}

# 2. Try to encrypt (should fail)
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "Authorization: Hmac ..." \
  -d '...'
# HTTP 503: {"error":"KMS_LOCKED","message":"..."}

# 3. Unlock with shares
curl -X POST http://localhost:8080/api/v1/admin/ceremony/unlock \
  -H "Authorization: Hmac ..." \
  -d '{"shares":["share_1","share_2","share_3"]}'
# {"status":"READY"}

# 4. Lock via CLI (no auth needed)
docker exec kms-container kms-service lock
# 🔒 Locking KMS...
# ✅ KMS successfully locked.

# 5. Verify locked
curl http://localhost:8080/status
# {"status":"LOCKED","manifest_loaded":true}
```

---

## Environment Variables (Full List)

```bash
# Enable HTTP lock endpoint (default: false)
CRYPTO__ENABLE_HTTP_LOCK=true

# Also include other crypto settings
CRYPTO__ENABLE_HTTP_REWRAP=false
CRYPTO__CURRENT_MASTER_KEY_VERSION=1
CRYPTO__DEFAULT_KEY_TTL_DAYS=365
```

---

## Troubleshooting

### Lock fails with "AppState initialization error"

- Ensure MongoDB and Redis are running
- Check configuration file paths

### HTTP lock endpoint returns 404

- Confirm `CRYPTO__ENABLE_HTTP_LOCK=true` is set
- Restart server after configuration change

### Lock command clears key but endpoints still work

- Check that middleware is properly wired in `routes.rs`
- Verify `state.is_unlocked()` is being checked

### Zeroization not happening

- Confirm `SecureStorageKey` derives `ZeroizeOnDrop`
- Arc reference count should reach 0 when cleared
- Use memory analysis tools (valgrind, asan) to verify

---

## Architecture Decisions

1. **Atomic Flag for Fast Checks**: The `kms_unlocked: Arc<AtomicBool>` allows quick synchronous checks without lock contention during health checks.

2. **RwLock for Key Storage**: `Arc<RwLock<Option<Arc<SecureStorageKey>>>>` provides safe concurrent reads of the storage key while allowing writes to clear it.

3. **Conditional HTTP Route**: The lock endpoint is wired at router construction time, so disabled routes return 404 (not caught by middleware).

4. **CLI Lock Over HTTP**: CLI lock is preferred because it avoids network exposure and doesn't require authentication management.

---

## References

- [Shamir's Secret Sharing (Ceremony)](./BOOTSTRAP_GUIDE.md)
- [KMS Status & Health](./API.md#health-status)
- [Admin API Endpoints](./API.md#admin-api)
