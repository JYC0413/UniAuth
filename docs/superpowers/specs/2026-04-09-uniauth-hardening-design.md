# UniAuth Hardening Design

**Date:** 2026-04-09  
**Scope:** PostgreSQL migration + TOTP 2FA + Security fixes  
**Status:** Approved

---

## Overview

Three parallel work blocks to harden UniAuth before wider deployment:

1. **PostgreSQL Migration** — move from Supabase hosted DB to self-managed Docker PostgreSQL
2. **TOTP 2FA** — mandatory two-factor authentication via Google Authenticator (TOTP)
3. **Security Fixes** — address critical and high-severity issues found in code review

Callers: web frontend (login, 2FA) + backend services (permission verification only, no login).

---

## Work Block 1: PostgreSQL Migration

### Goal

Replace Supabase hosted PostgreSQL with a self-managed PostgreSQL instance running in Docker. UniAuth only uses Supabase as a database host — no Supabase-specific features (Auth, Realtime, Storage, etc.) are in use.

### Changes

**docker-compose.yml** (new file):
- Service `db`: `postgres:16-alpine`, persisted volume, env-driven credentials
- Service `uniauth`: built from local Dockerfile, depends on `db`

**Environment variables** (new/changed):

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `APP_ENV` | No | `development` | `production` enables SSL + Secure cookie |
| `DB_HOST` | Yes | — | Fail startup if missing |
| `DB_PORT` | No | `5432` | |
| `DB_USER` | Yes | — | Fail startup if missing |
| `DB_PASSWORD` | Yes | — | Fail startup if missing |
| `DB_NAME` | Yes | — | Fail startup if missing |
| `DB_TIMEZONE` | No | `UTC` | Replaces hardcoded `Asia/Shanghai` |
| `DB_SSL_MODE` | No | `disable` (dev) / `require` (prod) | Auto-set from APP_ENV if not overridden |
| `JWT_SECRET` | Yes | — | **Fail startup if missing** |
| `CORS_ALLOWED_ORIGINS` | No | `""` (no CORS) | Comma-separated list |

**Startup validation** (`config/config.go`):

```go
required := []string{"DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET"}
for _, key := range required {
    if os.Getenv(key) == "" {
        log.Fatalf("required environment variable %s is not set", key)
    }
}
```

**Data migration** (one-time script, documented in README):
```bash
# Export from Supabase
pg_dump $SUPABASE_DSN > backup.sql

# Import to new instance
psql $NEW_DSN < backup.sql
```

---

## Work Block 2: TOTP 2FA

### Dependency

`github.com/pquerna/otp` — standard RFC 6238 TOTP implementation.

### Database Changes

```sql
ALTER TABLE sys_users
  ADD COLUMN totp_secret  VARCHAR(64) DEFAULT NULL,
  ADD COLUMN totp_enabled BOOLEAN     NOT NULL DEFAULT FALSE;
```

- `totp_secret`: base32-encoded TOTP secret; NULL until user completes enrollment
- `totp_enabled`: set to `true` only after user successfully verifies their first code (prevents partial enrollment)

### Token Types

Introduce a **pre-auth token** — a short-lived JWT (5 minutes) issued after password verification, before TOTP is confirmed.

JWT claims:
```go
type PreAuthClaims struct {
    UserID    uint   `json:"user_id"`
    TokenType string `json:"token_type"` // always "pre_auth"
    jwt.RegisteredClaims
}
```

Auth middleware change: reject any token with `token_type == "pre_auth"` on all routes **except** `/api/v1/auth/totp/*`.

### Modified Endpoint

`POST /api/v1/auth/login`

No longer returns a full `auth_token` directly. Returns:

```json
// Case 1: user has not enrolled TOTP yet
{ "status": "totp_setup_required", "pre_auth_token": "<jwt>" }

// Case 2: user already enrolled
{ "status": "totp_required", "pre_auth_token": "<jwt>" }
```

### New Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/v1/auth/totp/setup` | pre_auth_token (totp_secret must be NULL) | Generate secret + QR code (base64 PNG) |
| `POST` | `/api/v1/auth/totp/enroll` | pre_auth_token | Verify first TOTP code, save secret, return full auth_token |
| `POST` | `/api/v1/auth/totp/verify` | pre_auth_token | Verify TOTP code for enrolled user, return full auth_token |
| `POST` | `/api/v1/admin/users/:id/totp/reset` | auth_token + admin bit | Clear totp_secret + set totp_enabled=false |

### Login Flows

**First-time login (not yet enrolled):**
```
POST /auth/login            → { status: "totp_setup_required", pre_auth_token }
GET  /auth/totp/setup       → { qr_code_base64, secret }   [user scans QR]
POST /auth/totp/enroll      → { code: "123456" }
                            ← saves secret, totp_enabled=true, returns auth_token
```

**Returning user (already enrolled):**
```
POST /auth/login            → { status: "totp_required", pre_auth_token }
POST /auth/totp/verify      → { code: "123456" }
                            ← returns auth_token
```

**Admin resets a user's TOTP (user lost device):**
```
POST /admin/users/:id/totp/reset
     → clears totp_secret, sets totp_enabled=false
     → user goes through first-time enrollment flow on next login
```

### QR Code Response Format

```json
{
  "qr_code_base64": "data:image/png;base64,<...>",
  "secret": "JBSWY3DPEHPK3PXP"
}
```

The `secret` field is shown so users can manually enter it if QR scanning fails.

---

## Work Block 3: Security Fixes

### Required Fixes

**1. Admin permission check** (`admin_handler.go:688`)

Bit 0 of the `uniauth-admin` app is reserved as the "admin access" permission. A seed entry must exist in `sys_permissions` for the `uniauth-admin` app with `bit_index=0` and `permission_code="admin.access"` — the existing `setup_admin.go` / `setup_admin_test.go` already handles this seeding; verify it sets bit_index=0 for the first permission. Change the middleware check from "mask != 0" to "bit 0 is set":

```go
// Before
if finalMask.Cmp(big.NewInt(0)) == 0 { ... }

// After
adminBit := new(big.Int).SetBit(new(big.Int), 0, 1)
if new(big.Int).And(finalMask, adminBit).Cmp(adminBit) != 0 { ... }
```

**2. JWT_SECRET required** (`config/config.go:38`)

Remove the `"your-secret-key"` default. Covered by startup validation in Work Block 1.

**3. Cookie: Secure + SameSite** (`auth_handler.go:68`)

```go
secure := cfg.AppEnv == "production"
c.SetCookie("auth_token", token, 3600*24, "/", "", secure, true)
c.Header("Set-Cookie", c.Writer.Header().Get("Set-Cookie")+"; SameSite=Strict")
```

`SameSite=Strict` prevents browsers from sending the cookie on any cross-origin request, eliminating CSRF risk without requiring token-based CSRF protection.

**4. Login rate limiting** (`main.go` + new middleware)

Implement IP-based rate limiting using `golang.org/x/time/rate`:
- Limit: 10 requests/minute per IP on `POST /api/v1/auth/login`
- Response on exceed: `429 Too Many Requests`

**5. `parseUint` error handling** (`admin_handler.go`)

```go
// Before
func parseUint(s string) uint64 {
    v, _ := strconv.ParseUint(s, 10, 64)
    return v
}

// After: returns (uint64, error); callers return 400 on error
```

**6. BitIndex overflow check** (`admin_handler.go`)

```go
if nextIndex > 32767 {
    c.JSON(http.StatusBadRequest, gin.H{"error": "permission limit reached (max 32767)"})
    return
}
```

### Recommended Fixes

**7. CORS** — add `github.com/gin-contrib/cors` middleware, read `CORS_ALLOWED_ORIGINS` env var. Default: reject all cross-origin requests.

**8. Request size limit** — add middleware in `main.go` limiting request body to 4MB.

**9. Token blacklist cleanup** — on startup, delete all rows where `expiry_time < NOW()`. Launch background goroutine to repeat every 24 hours.

**10. List pagination** — `ListApps` and `ListUsers` accept `?page=1&limit=20`. Default limit: 20. Max limit: 100.

### Database: New Indexes

```sql
CREATE INDEX idx_token_blacklist_token  ON sys_token_blacklist(token);
CREATE INDEX idx_token_blacklist_expiry ON sys_token_blacklist(expiry_time);
```

### Deferred

| Item | Reason |
|------|--------|
| Audit logging | Significant scope; separate plan |
| Graceful shutdown | Operational concern; low urgency |
| Health check endpoint | Simple add-on; can be done anytime |

---

## File Change Summary

| File | Change |
|------|--------|
| `docker-compose.yml` | New file |
| `.env.example` | New file with all variables documented |
| `internal/config/config.go` | Startup validation, remove JWT default, add AppEnv/CORS/Timezone |
| `internal/database/db.go` | Configurable sslmode, timezone, add blacklist cleanup goroutine |
| `internal/handler/auth_handler.go` | Login returns pre_auth_token; cookie Secure+SameSite; new TOTP handlers |
| `internal/handler/admin_handler.go` | Fix admin bit check; fix parseUint; fix BitIndex overflow; add TOTP reset; add pagination |
| `internal/middleware/auth_middleware.go` | Reject pre_auth_token on protected routes; add rate limiter middleware |
| `internal/model/user.go` | Add totp_secret, totp_enabled fields |
| `main.go` | Wire CORS middleware, request size limit, rate limiter |
| `go.mod` / `go.sum` | Add pquerna/otp, gin-contrib/cors, golang.org/x/time |
| SQL schema | ADD COLUMN for TOTP; CREATE INDEX for blacklist |
