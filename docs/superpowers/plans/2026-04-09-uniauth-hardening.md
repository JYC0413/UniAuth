# UniAuth Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate from Supabase to self-managed Docker PostgreSQL, add mandatory TOTP 2FA, and fix all critical/high security issues.

**Architecture:** Three sequential work blocks. Block 1 (config + Docker) must complete first because Blocks 2 and 3 depend on the new config fields. Block 2 (TOTP) and Block 3 (security fixes) can largely proceed in parallel once Block 1 is done, but Block 2 changes to `auth_handler.go` and `main.go` must land before Block 3's changes to those same files to avoid conflicts.

**Tech Stack:** Go 1.24, Gin, GORM, PostgreSQL 16, `github.com/pquerna/otp` (TOTP), `github.com/gin-contrib/cors`, `golang.org/x/time/rate` (rate limiting), Docker Compose.

---

## File Map

| File | Action | What changes |
|------|--------|-------------|
| `internal/config/config.go` | Modify | Add `AppEnv`, `DBTimezone`, `DBSSLMode`, `CORSAllowedOrigins`; remove JWT default; add startup validation |
| `internal/config/config_test.go` | Create | Tests for config loading |
| `internal/database/db.go` | Modify | Use configurable DSN fields; add blacklist cleanup goroutine |
| `Dockerfile` | Create | Multi-stage build for production image |
| `docker-compose.yml` | Create | PostgreSQL 16 + UniAuth services |
| `.env.example` | Create | All required/optional env vars documented |
| `create_table_sql/migration_totp_blacklist.sql` | Create | ALTER TABLE for TOTP columns + CREATE INDEX for blacklist |
| `internal/model/models.go` | Modify | Add `TOTPSecret *string` + `TOTPEnabled bool` to `SysUser` |
| `internal/utils/jwt.go` | Modify | Add `TokenType` to `Claims`; add `GeneratePreAuthToken` |
| `internal/utils/jwt_test.go` | Create | Tests for pre-auth token generation and parsing |
| `internal/middleware/auth_middleware.go` | Modify | Reject `pre_auth` tokens; add blacklist index benefit |
| `internal/middleware/pre_auth_middleware.go` | Create | Validate `pre_auth` tokens for TOTP routes |
| `internal/middleware/rate_limiter.go` | Create | IP-based rate limiter (10 req/min) |
| `internal/middleware/rate_limiter_test.go` | Create | Tests for rate limiting behavior |
| `internal/handler/totp_handler.go` | Create | `TOTPSetup`, `TOTPEnroll`, `TOTPVerify`, `TOTPReset` handlers |
| `internal/handler/auth_handler.go` | Modify | Login returns pre-auth token + status; fix cookie SameSite |
| `internal/handler/admin_handler.go` | Modify | Fix admin bit check; fix `parseUint`; fix BitIndex overflow; add pagination |
| `main.go` | Modify | Wire CORS, request size limit, rate limiter, TOTP routes, cleanup goroutine |
| `go.mod` / `go.sum` | Modify | Add new dependencies |

---

## Task 1: Config Overhaul

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"testing"
)

func TestLoadConfig_SetsAllFields(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	os.Setenv("JWT_SECRET", "test-secret-32-chars-minimum-ok")
	os.Setenv("DB_HOST", "testhost")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_PASSWORD", "testpass")
	os.Setenv("DB_NAME", "testdb")
	os.Setenv("DB_TIMEZONE", "Asia/Shanghai")
	os.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")
	defer func() {
		for _, k := range []string{"APP_ENV", "JWT_SECRET", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_TIMEZONE", "CORS_ALLOWED_ORIGINS"} {
			os.Unsetenv(k)
		}
	}()

	LoadConfig()

	if AppConfig.AppEnv != "production" {
		t.Errorf("expected AppEnv=production, got %s", AppConfig.AppEnv)
	}
	if AppConfig.DBTimezone != "Asia/Shanghai" {
		t.Errorf("expected DBTimezone=Asia/Shanghai, got %s", AppConfig.DBTimezone)
	}
	if AppConfig.DBSSLMode != "require" {
		t.Errorf("expected DBSSLMode=require in production, got %s", AppConfig.DBSSLMode)
	}
	if AppConfig.CORSAllowedOrigins != "https://app.example.com" {
		t.Errorf("expected CORSAllowedOrigins set, got %s", AppConfig.CORSAllowedOrigins)
	}
	if AppConfig.JWTSecret != "test-secret-32-chars-minimum-ok" {
		t.Errorf("JWTSecret not loaded correctly")
	}
}

func TestLoadConfig_DevModeUsesDisableSSL(t *testing.T) {
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	os.Setenv("DB_NAME", "uniauth")
	os.Unsetenv("APP_ENV")
	os.Unsetenv("DB_SSL_MODE")
	defer func() {
		for _, k := range []string{"JWT_SECRET", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"} {
			os.Unsetenv(k)
		}
	}()

	LoadConfig()

	if AppConfig.DBSSLMode != "disable" {
		t.Errorf("expected DBSSLMode=disable in development, got %s", AppConfig.DBSSLMode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/juyichen/myCodePlace/GlimpseEngine/UniAuth
go test ./internal/config/... -v
```

Expected: compile error or FAIL — `AppEnv`, `DBTimezone`, `DBSSLMode`, `CORSAllowedOrigins` fields don't exist yet.

- [ ] **Step 3: Rewrite `internal/config/config.go`**

```go
package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort         string
	AppEnv             string // "development" | "production"
	DatabaseURL        string // Full DSN takes priority over individual fields
	DBHost             string
	DBUser             string
	DBPassword         string
	DBName             string
	DBPort             string
	DBTimezone         string
	DBSSLMode          string
	JWTSecret          string
	CORSAllowedOrigins string // Comma-separated list; empty = no CORS
}

var AppConfig *Config

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Validate required variables before building config
	required := []string{"DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET"}
	for _, key := range required {
		if os.Getenv(key) == "" {
			log.Fatalf("required environment variable %s is not set", key)
		}
	}

	appEnv := getEnv("APP_ENV", "development")

	// Default SSL mode based on environment (can be overridden explicitly)
	defaultSSL := "disable"
	if appEnv == "production" {
		defaultSSL = "require"
	}

	AppConfig = &Config{
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		AppEnv:             appEnv,
		DatabaseURL:        getEnv("DATABASE_URL", ""),
		DBHost:             getEnv("DB_HOST", ""),
		DBUser:             getEnv("DB_USER", ""),
		DBPassword:         getEnv("DB_PASSWORD", ""),
		DBName:             getEnv("DB_NAME", ""),
		DBPort:             getEnv("DB_PORT", "5432"),
		DBTimezone:         getEnv("DB_TIMEZONE", "UTC"),
		DBSSLMode:          getEnv("DB_SSL_MODE", defaultSSL),
		JWTSecret:          getEnv("JWT_SECRET", ""),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	strValue := getEnv(key, "")
	if strValue == "" {
		return fallback
	}
	val, err := strconv.Atoi(strValue)
	if err != nil {
		log.Printf("Invalid integer for env %s: %v. Using fallback %d", key, err, fallback)
		return fallback
	}
	return val
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/config/... -v
```

Expected: `PASS` for both test cases.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: overhaul config with AppEnv, SSL mode, timezone, CORS, required-var validation"
```

---

## Task 2: Database Layer — Configurable DSN + Blacklist Cleanup

**Files:**
- Modify: `internal/database/db.go`

- [ ] **Step 1: Rewrite `internal/database/db.go`**

```go
package database

import (
	"fmt"
	"log"
	"time"

	"UniAuth/internal/config"
	"UniAuth/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	var dsn string
	if config.AppConfig.DatabaseURL != "" {
		dsn = config.AppConfig.DatabaseURL
	} else {
		dsn = fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
			config.AppConfig.DBHost,
			config.AppConfig.DBUser,
			config.AppConfig.DBPassword,
			config.AppConfig.DBName,
			config.AppConfig.DBPort,
			config.AppConfig.DBSSLMode,
			config.AppConfig.DBTimezone,
		)
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	log.Println("Database connected successfully")
}

// StartBlacklistCleanup deletes expired token blacklist entries.
// Runs once immediately, then every 24 hours in a background goroutine.
func StartBlacklistCleanup() {
	cleanupOnce := func() {
		result := DB.Where("expires_at < ?", time.Now()).Delete(&model.SysTokenBlacklist{})
		if result.Error != nil {
			log.Printf("Blacklist cleanup error: %v", result.Error)
		} else {
			log.Printf("Blacklist cleanup: deleted %d expired entries", result.RowsAffected)
		}
	}

	cleanupOnce()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupOnce()
		}
	}()
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/database/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/database/db.go
git commit -m "feat: configurable DSN (sslmode, timezone) + blacklist cleanup goroutine"
```

---

## Task 3: Docker Infrastructure

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.env.example`

- [ ] **Step 1: Create `Dockerfile`**

```dockerfile
# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o uniauth .

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/uniauth .
COPY --from=builder /app/web ./web
EXPOSE 8080
CMD ["./uniauth"]
```

- [ ] **Step 2: Create `docker-compose.yml`**

```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d ${DB_NAME}"]
      interval: 5s
      timeout: 5s
      retries: 5

  uniauth:
    build: .
    ports:
      - "${SERVER_PORT:-8080}:8080"
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy

volumes:
  postgres_data:
```

- [ ] **Step 3: Create `.env.example`**

```bash
# Application
SERVER_PORT=8080
APP_ENV=development        # "development" or "production"

# Database (required)
DB_HOST=db                 # Use "db" inside Docker Compose, "localhost" for local dev
DB_PORT=5432
DB_USER=uniauth
DB_PASSWORD=change_me_in_production
DB_NAME=uniauth
DB_TIMEZONE=UTC            # e.g. "Asia/Shanghai"
DB_SSL_MODE=               # Leave empty to auto-select based on APP_ENV

# JWT (required — no default, server will not start without this)
JWT_SECRET=replace_with_a_random_32_plus_char_secret

# CORS (optional — empty means no cross-origin requests allowed)
# CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

- [ ] **Step 4: Verify Docker Compose syntax**

```bash
docker compose config
```

Expected: Validated config printed, no errors.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml .env.example
git commit -m "feat: add Docker multi-stage build + docker-compose with PostgreSQL 16"
```

---

## Task 4: SQL Migration — TOTP Columns + Blacklist Indexes

**Files:**
- Create: `create_table_sql/migration_totp_blacklist.sql`

- [ ] **Step 1: Create the migration file**

```sql
-- Migration: Add TOTP support to sys_users and performance indexes on sys_token_blacklist
-- Run this against your existing database. For fresh Docker setups, include in schema init.

-- TOTP fields on sys_users
ALTER TABLE sys_users
  ADD COLUMN IF NOT EXISTS totp_secret  VARCHAR(64)  DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN      NOT NULL DEFAULT FALSE;

-- Performance indexes on sys_token_blacklist
CREATE INDEX IF NOT EXISTS idx_token_blacklist_token
  ON sys_token_blacklist(token);

CREATE INDEX IF NOT EXISTS idx_token_blacklist_expiry
  ON sys_token_blacklist(expires_at);
```

- [ ] **Step 2: Apply the migration to your database**

For Supabase (before migration):
```bash
psql $SUPABASE_DSN < create_table_sql/migration_totp_blacklist.sql
```

For new Docker PostgreSQL (after `docker compose up -d db`):
```bash
psql "host=localhost port=5432 user=uniauth password=change_me_in_production dbname=uniauth" \
  < create_table_sql/migration_totp_blacklist.sql
```

Expected output:
```
ALTER TABLE
CREATE INDEX
CREATE INDEX
```

- [ ] **Step 3: Commit**

```bash
git add create_table_sql/migration_totp_blacklist.sql
git commit -m "feat: SQL migration for TOTP columns and token blacklist indexes"
```

---

## Task 5: Model Update — TOTP Fields on SysUser

**Files:**
- Modify: `internal/model/models.go`

- [ ] **Step 1: Add TOTP fields to `SysUser`**

In `internal/model/models.go`, find the `SysUser` struct (around line 77) and add the two TOTP fields:

```go
// Before (SysUser struct):
type SysUser struct {
	ID        uuid.UUID     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Username  string        `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Email     string        `gorm:"type:varchar(100);uniqueIndex" json:"email"`
	Password  string        `gorm:"type:varchar(255);not null" json:"-"`
	Status    int16         `gorm:"type:smallint;default:1" json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	UserRoles []SysUserRole `gorm:"foreignKey:UserID" json:"user_roles,omitempty"`
}

// After:
type SysUser struct {
	ID          uuid.UUID     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Username    string        `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Email       string        `gorm:"type:varchar(100);uniqueIndex" json:"email"`
	Password    string        `gorm:"type:varchar(255);not null" json:"-"`
	Status      int16         `gorm:"type:smallint;default:1" json:"status"`
	TOTPSecret  *string       `gorm:"type:varchar(64)" json:"-"`       // NULL until setup; never exposed in JSON
	TOTPEnabled bool          `gorm:"type:boolean;not null;default:false" json:"totp_enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	UserRoles   []SysUserRole `gorm:"foreignKey:UserID" json:"user_roles,omitempty"`
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/model/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/model/models.go
git commit -m "feat: add TOTPSecret and TOTPEnabled fields to SysUser model"
```

---

## Task 6: JWT — Pre-Auth Token Support

**Files:**
- Modify: `internal/utils/jwt.go`
- Create: `internal/utils/jwt_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/utils/jwt_test.go`:

```go
package utils

import (
	"testing"

	"UniAuth/internal/config"
	"github.com/google/uuid"
)

func init() {
	// Provide a config for tests
	config.AppConfig = &config.Config{
		JWTSecret: "test-secret-for-jwt-tests-minimum",
	}
}

func TestGeneratePreAuthToken_HasCorrectTokenType(t *testing.T) {
	userID := uuid.New()
	token, err := GeneratePreAuthToken(userID, "SELF")
	if err != nil {
		t.Fatalf("GeneratePreAuthToken failed: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.TokenType != "pre_auth" {
		t.Errorf("expected token_type=pre_auth, got %s", claims.TokenType)
	}
	if claims.UserID != userID {
		t.Errorf("UserID mismatch")
	}
	if claims.DataScope != "SELF" {
		t.Errorf("expected DataScope=SELF, got %s", claims.DataScope)
	}
}

func TestGenerateToken_HasEmptyTokenType(t *testing.T) {
	userID := uuid.New()
	token, err := GenerateToken(userID, "ALL")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.TokenType != "" {
		t.Errorf("expected empty token_type for regular token, got %s", claims.TokenType)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/utils/... -v
```

Expected: compile error — `TokenType` field and `GeneratePreAuthToken` don't exist yet.

- [ ] **Step 3: Update `internal/utils/jwt.go`**

```go
package utils

import (
	"time"

	"UniAuth/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID    uuid.UUID `json:"uid"`
	DataScope string    `json:"data_scope,omitempty"`
	TokenType string    `json:"token_type,omitempty"` // "pre_auth" for TOTP step; "" for full auth token
	jwt.RegisteredClaims
}

func GenerateToken(userID uuid.UUID, dataScope string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		DataScope: dataScope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "auth.company.com",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

// GeneratePreAuthToken issues a 5-minute token used only for the TOTP verification step.
// It carries the DataScope so it can be forwarded to GenerateToken after TOTP passes.
func GeneratePreAuthToken(userID uuid.UUID, dataScope string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		DataScope: dataScope,
		TokenType: "pre_auth",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "auth.company.com",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

func ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.AppConfig.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}
	return claims, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/utils/... -v
```

Expected: `PASS` for both test cases.

- [ ] **Step 5: Commit**

```bash
git add internal/utils/jwt.go internal/utils/jwt_test.go
git commit -m "feat: add TokenType to JWT claims and GeneratePreAuthToken for TOTP flow"
```

---

## Task 7: Middleware — Auth Update + Pre-Auth + Rate Limiter

**Files:**
- Modify: `internal/middleware/auth_middleware.go`
- Create: `internal/middleware/pre_auth_middleware.go`
- Create: `internal/middleware/rate_limiter.go`
- Create: `internal/middleware/rate_limiter_test.go`

- [ ] **Step 1: Write the failing rate limiter test**

Create `internal/middleware/rate_limiter_test.go`:

```go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginRateLimiter_Allows10ThenBlocks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/login", LoginRateLimiter(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Reset the limiter for this test IP
	loginLimiter = newIPRateLimiter(10.0/60, 10) // 10 per minute, burst 10

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 11th request should be rate-limited
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -v -run TestLoginRateLimiter
```

Expected: compile error — `LoginRateLimiter`, `loginLimiter`, `newIPRateLimiter` not defined.

- [ ] **Step 3: Create `internal/middleware/rate_limiter.go`**

```go
package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

func newIPRateLimiter(r rate.Limit, b int) *ipRateLimiter {
	return &ipRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter
}

// loginLimiter: 10 requests per minute per IP, burst of 10
var loginLimiter = newIPRateLimiter(10.0/60, 10)

func LoginRateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !loginLimiter.getLimiter(ip).Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many login attempts, please try again later",
			})
			return
		}
		c.Next()
	}
}
```

- [ ] **Step 4: Install golang.org/x/time**

```bash
go get golang.org/x/time/rate
```

- [ ] **Step 5: Run rate limiter test**

```bash
go test ./internal/middleware/... -v -run TestLoginRateLimiter
```

Expected: `PASS`.

- [ ] **Step 6: Update `internal/middleware/auth_middleware.go` to reject pre_auth tokens**

Replace the full file:

```go
package middleware

import (
	"net/http"
	"time"

	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			return
		}

		var count int64
		database.DB.Model(&model.SysTokenBlacklist{}).Where("token = ?", tokenString).Count(&count)
		if count > 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token invalidated"})
			return
		}

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if time.Now().After(claims.ExpiresAt.Time) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Pre-auth tokens are only valid on TOTP routes — reject them here
		if claims.TokenType == "pre_auth" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "TOTP verification required"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	if token, err := c.Cookie("auth_token"); err == nil {
		return token
	}
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
```

- [ ] **Step 7: Create `internal/middleware/pre_auth_middleware.go`**

```go
package middleware

import (
	"net/http"
	"time"

	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
)

// PreAuthMiddleware validates tokens issued after password verification but before TOTP.
// Only accepts tokens with token_type == "pre_auth". Reads from Authorization header only
// (pre_auth tokens are never stored in cookies).
func PreAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) <= 7 || auth[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Pre-auth token required"})
			return
		}
		tokenString := auth[7:]

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if time.Now().After(claims.ExpiresAt.Time) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		if claims.TokenType != "pre_auth" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("dataScope", claims.DataScope)
		c.Next()
	}
}
```

- [ ] **Step 8: Verify everything compiles**

```bash
go build ./internal/middleware/...
```

Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add internal/middleware/auth_middleware.go internal/middleware/pre_auth_middleware.go \
        internal/middleware/rate_limiter.go internal/middleware/rate_limiter_test.go \
        go.mod go.sum
git commit -m "feat: add pre-auth middleware, rate limiter, update auth middleware to reject pre_auth tokens"
```

---

## Task 8: TOTP Handlers

**Files:**
- Create: `internal/handler/totp_handler.go`

- [ ] **Step 1: Install TOTP library**

```bash
go get github.com/pquerna/otp
go get github.com/pquerna/otp/totp
```

- [ ] **Step 2: Create `internal/handler/totp_handler.go`**

```go
package handler

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"

	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type TOTPCodeRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// TOTPSetup generates a new TOTP secret and QR code for a user who has not yet enrolled.
// Requires: pre_auth_token in Authorization header (user must not have totp_secret set).
func TOTPSetup(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.TOTPSecret != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP already configured, contact admin to reset"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "UniAuth",
		AccountName: user.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP secret"})
		return
	}

	secret := key.Secret()
	if err := database.DB.Model(&user).Update("totp_secret", secret).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP secret"})
		return
	}

	img, err := key.Image(200, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode QR code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"qr_code_base64": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		"secret":         secret, // shown so user can manually type it if QR scan fails
	})
}

// TOTPEnroll verifies the first TOTP code from the user, marks TOTP as enabled,
// and returns a full auth_token. Called after TOTPSetup.
// Requires: pre_auth_token in Authorization header.
func TOTPEnroll(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	dataScope := c.GetString("dataScope")

	var req TOTPCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.TOTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Call /totp/setup first"})
		return
	}
	if user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP already enrolled"})
		return
	}

	if !totp.Validate(req.Code, *user.TOTPSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
		return
	}

	if err := database.DB.Model(&user).Update("totp_enabled", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable TOTP"})
		return
	}

	token, err := utils.GenerateToken(userID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"message": "TOTP enrollment successful", "token": token})
}

// TOTPVerify validates a TOTP code for an already-enrolled user and issues a full auth_token.
// Requires: pre_auth_token in Authorization header.
func TOTPVerify(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	dataScope := c.GetString("dataScope")

	var req TOTPCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP not enrolled"})
		return
	}

	if !totp.Validate(req.Code, *user.TOTPSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
		return
	}

	token, err := utils.GenerateToken(userID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

// TOTPReset clears a user's TOTP enrollment. Admin-only.
// After reset, the user goes through TOTPSetup + TOTPEnroll on next login.
func TOTPReset(c *gin.Context) {
	userIDStr := c.Param("user_id")
	targetID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	result := database.DB.Model(&model.SysUser{}).Where("id = ?", targetID).
		Updates(map[string]interface{}{
			"totp_secret":  nil,
			"totp_enabled": false,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset TOTP"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP reset successful"})
}
```

- [ ] **Step 3: Verify it compiles**

```bash
go build ./internal/handler/...
```

Expected: no errors. (Note: `setAuthCookie` doesn't exist yet — it will be added in Task 9.)

- [ ] **Step 4: Commit**

```bash
git add internal/handler/totp_handler.go go.mod go.sum
git commit -m "feat: add TOTP setup/enroll/verify/reset handlers"
```

---

## Task 9: Update Login Handler — Pre-Auth Flow + Cookie Fix

**Files:**
- Modify: `internal/handler/auth_handler.go`

- [ ] **Step 1: Rewrite the `Login` function and add `setAuthCookie` helper**

Replace the full `internal/handler/auth_handler.go`:

```go
package handler

import (
	"net/http"
	"time"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Determine DataScope (highest scope across all user roles)
	maxScope := 1
	var userRoles []model.SysUserRole
	if err := database.DB.Preload("Role.DataScope").Where("user_id = ?", user.ID).Find(&userRoles).Error; err == nil {
		for _, ur := range userRoles {
			if ur.Role.DataScope != nil && ur.Role.DataScope.ScopeType > maxScope {
				maxScope = ur.Role.DataScope.ScopeType
			}
		}
	}
	scopeMap := map[int]string{1: "SELF", 2: "DEPT", 3: "ALL", 4: "CUSTOM"}
	dataScope := scopeMap[maxScope]

	// Issue a short-lived pre-auth token; TOTP verification issues the full token
	preAuthToken, err := utils.GeneratePreAuthToken(user.ID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	if user.TOTPSecret == nil {
		// User has never set up TOTP — direct them to enrollment
		c.JSON(http.StatusOK, gin.H{
			"status":          "totp_setup_required",
			"pre_auth_token":  preAuthToken,
		})
	} else {
		// User is enrolled — direct them to verify
		c.JSON(http.StatusOK, gin.H{
			"status":         "totp_required",
			"pre_auth_token": preAuthToken,
		})
	}
}

func Logout(c *gin.Context) {
	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		tokenString = c.GetHeader("Authorization")
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
	}

	if tokenString != "" {
		claims, err := utils.ParseToken(tokenString)
		if err == nil {
			blacklistEntry := model.SysTokenBlacklist{
				Token:     tokenString,
				ExpiresAt: claims.ExpiresAt.Time,
				CreatedAt: time.Now(),
			}
			database.DB.Create(&blacklistEntry)
		}
	}

	c.SetCookie("auth_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := model.SysUser{
		Username:  req.Username,
		Password:  string(hashedPassword),
		Email:     req.Email,
		Status:    1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "uid": user.ID})
}

// setAuthCookie sets the auth_token cookie with Secure and SameSite=Strict.
// Secure is true only in production (APP_ENV=production).
func setAuthCookie(c *gin.Context, token string) {
	secure := config.AppConfig.AppEnv == "production"
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		MaxAge:   3600 * 24,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/handler/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/handler/auth_handler.go
git commit -m "feat: login now returns pre_auth_token for 2FA flow; fix cookie SameSite=Strict + Secure"
```

---

## Task 10: Admin Handler Security Fixes

**Files:**
- Modify: `internal/handler/admin_handler.go`

This task makes four independent changes to `admin_handler.go`. Make them one at a time, compiling after each.

### 10a — Fix Admin Permission Check (Critical)

- [ ] **Step 1: Replace the admin mask check at line 688**

Find this block in `CheckAdminPermission`:

```go
// 3. Check if mask is non-zero (Basic check: is an admin)
if finalMask.Cmp(big.NewInt(0)) == 0 {
    c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
    return
}
```

Replace with:

```go
// 3. Check that bit 0 (admin.access) is set in the uniauth-admin mask.
// Bit 0 is reserved for "admin.access" — the first permission created by setup_admin.go.
// Any role without bit 0 cannot access admin endpoints, regardless of other permissions.
adminBit := new(big.Int).SetBit(new(big.Int), 0, 1)
if new(big.Int).And(finalMask, adminBit).Cmp(adminBit) != 0 {
    c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
    return
}
```

**Wait — verify bit 0 logic before proceeding:**

The condition `And(finalMask, adminBit).Cmp(adminBit) != 0` is incorrect. Trace through:
- If bit 0 IS set: `And(finalMask, adminBit)` = 1 = adminBit → `Cmp(adminBit)` = 0 → `!= 0` is **false** → does NOT abort ✓  
- If bit 0 is NOT set: `And(finalMask, adminBit)` = 0 → `Cmp(adminBit)` = -1 → `!= 0` is **true** → aborts ✓

Logic is correct. The condition aborts when bit 0 is absent.

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/handler/...
```

### 10b — Fix BitIndex Overflow

- [ ] **Step 3: Add overflow check in `CreateAppPermission`**

Find this block (around line 115):

```go
nextIndex := 0
if maxIndex != nil {
    nextIndex = *maxIndex + 1
}

// Removed 127 limit check for infinite scalability
```

Replace with:

```go
nextIndex := 0
if maxIndex != nil {
    nextIndex = *maxIndex + 1
}

if nextIndex > 32767 {
    c.JSON(http.StatusBadRequest, gin.H{"error": "permission limit reached (max 32767 per app)"})
    return
}
```

- [ ] **Step 4: Verify it compiles**

```bash
go build ./internal/handler/...
```

### 10c — Fix parseUint Error Handling

- [ ] **Step 5: Update `parseUint` to return an error**

Find the `parseUint` function (around line 486):

```go
func parseUint(s string) uint64 {
    v, _ := strconv.ParseUint(s, 10, 64)
    return v
}
```

Replace with:

```go
func parseUint(s string) (uint64, error) {
    return strconv.ParseUint(s, 10, 64)
}
```

- [ ] **Step 6: Fix all call sites of parseUint**

Search for all usages:

```bash
grep -n "parseUint" internal/handler/admin_handler.go
```

For every call site that looks like:
```go
someID := parseUint(c.Param("some_id"))
```

Change to:
```go
someID, err := parseUint(c.Param("some_id"))
if err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID"})
    return
}
```

- [ ] **Step 7: Verify it compiles**

```bash
go build ./internal/handler/...
```

### 10d — Add Pagination to ListApps and ListUsers

- [ ] **Step 8: Update `ListApps` to support pagination**

Find the `ListApps` function. After the `scope` variable is set and before the `query.Find(&apps)` call, add:

```go
page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
if page < 1 {
    page = 1
}
if limit < 1 || limit > 100 {
    limit = 20
}
offset := (page - 1) * limit

var total int64
query.Count(&total)
query = query.Offset(offset).Limit(limit)
```

And update the final JSON response to include pagination metadata:

```go
// Before:
c.JSON(http.StatusOK, gin.H{"data": apps})

// After:
c.JSON(http.StatusOK, gin.H{
    "data":  apps,
    "total": total,
    "page":  page,
    "limit": limit,
})
```

- [ ] **Step 9: Apply the same pagination pattern to `ListUsers`**

Find the `ListUsers` function. After the scope/query setup (around line 518, before `query.Find(&users)`), add the same pagination block:

```go
page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
if page < 1 {
    page = 1
}
if limit < 1 || limit > 100 {
    limit = 20
}
offset := (page - 1) * limit

var total int64
query.Count(&total)
query = query.Offset(offset).Limit(limit)
```

Update the response:

```go
// Before:
c.JSON(http.StatusOK, gin.H{"data": users})

// After:
c.JSON(http.StatusOK, gin.H{
    "data":  users,
    "total": total,
    "page":  page,
    "limit": limit,
})
```

- [ ] **Step 10: Verify full compile**

```bash
go build ./internal/handler/...
```

Expected: no errors.

- [ ] **Step 11: Commit**

```bash
git add internal/handler/admin_handler.go
git commit -m "fix: admin permission check now requires bit 0; fix parseUint errors; BitIndex overflow guard; add pagination to ListApps/ListUsers"
```

---

## Task 11: Wire Everything in main.go

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Install CORS library**

```bash
go get github.com/gin-contrib/cors
```

- [ ] **Step 2: Rewrite `main.go`**

```go
package main

import (
	"log"
	"net/http"
	"strings"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/handler"
	"UniAuth/internal/middleware"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	database.ConnectDB()
	database.StartBlacklistCleanup()

	r := gin.Default()

	// Request body size limit: 4MB
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<20)
		c.Next()
	})

	// CORS
	if origins := config.AppConfig.CORSAllowedOrigins; origins != "" {
		corsConfig := cors.DefaultConfig()
		corsConfig.AllowOrigins = strings.Split(origins, ",")
		corsConfig.AllowCredentials = true
		corsConfig.AddAllowHeaders("Authorization")
		r.Use(cors.New(corsConfig))
	}

	// Static / HTML
	r.Static("/static", "./web")
	r.LoadHTMLGlob("web/*.html")
	r.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "index.html", nil) })
	r.GET("/dashboard", func(c *gin.Context) { c.HTML(http.StatusOK, "dashboard.html", nil) })
	r.GET("/admin", func(c *gin.Context) { c.HTML(http.StatusOK, "admin.html", nil) })

	// Public routes
	r.POST("/api/v1/auth/login", middleware.LoginRateLimiter(), handler.Login)
	r.POST("/api/v1/auth/logout", handler.Logout)
	r.GET("/api/v1/meta/permissions", handler.GetPermissions)

	// TOTP routes — require pre_auth_token (issued by login, before full auth)
	totp := r.Group("/api/v1/auth/totp")
	totp.Use(middleware.PreAuthMiddleware())
	{
		totp.GET("/setup", handler.TOTPSetup)
		totp.POST("/enroll", handler.TOTPEnroll)
		totp.POST("/verify", handler.TOTPVerify)
	}

	// Protected routes — require full auth_token
	auth := r.Group("/api/v1/auth")
	auth.Use(middleware.AuthMiddleware())
	{
		auth.GET("/my-mask", handler.GetUserMask)
	}

	// Admin routes — require full auth_token + admin bit 0
	admin := r.Group("/api/v1/admin")
	admin.Use(middleware.AuthMiddleware())
	admin.Use(handler.CheckAdminPermission)
	{
		admin.GET("/apps", handler.ListApps)
		admin.POST("/apps", handler.CreateApp)

		admin.GET("/apps/:app_id/permissions", handler.ListAppPermissions)
		admin.POST("/apps/:app_id/permissions", handler.CreateAppPermission)
		admin.POST("/apps/:app_id/permissions/batch", handler.BatchCreateAppPermissions)
		admin.PUT("/permissions/:perm_id", handler.UpdateAppPermission)
		admin.DELETE("/permissions/:perm_id", handler.DeleteAppPermission)

		admin.GET("/apps/:app_id/roles", handler.ListAppRoles)
		admin.POST("/apps/:app_id/roles", handler.CreateAppRole)
		admin.GET("/roles/:role_id", handler.GetRole)
		admin.PUT("/roles/:role_id", handler.UpdateRole)

		admin.GET("/users", handler.ListUsers)
		admin.POST("/users", handler.CreateUser)
		admin.GET("/users/:user_id/apps/:app_id/role", handler.GetUserAppRole)
		admin.PUT("/users/:user_id/roles", handler.SetUserRole)
		admin.POST("/users/:user_id/totp/reset", handler.TOTPReset)
	}

	log.Printf("Server starting on port %s (env: %s)", config.AppConfig.ServerPort, config.AppConfig.AppEnv)
	if err := r.Run(":" + config.AppConfig.ServerPort); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
```

- [ ] **Step 3: Verify the full project builds**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 4: Run all tests**

```bash
go test ./... -v
```

Expected: all unit tests pass (config, utils/jwt, middleware/rate_limiter).

- [ ] **Step 5: Commit**

```bash
git add main.go go.mod go.sum
git commit -m "feat: wire CORS, request size limit, rate limiter, TOTP routes, admin TOTP reset in main.go"
```

---

## Task 12: Smoke Test with Docker

- [ ] **Step 1: Copy `.env.example` to `.env` and fill in values**

```bash
cp .env.example .env
# Edit .env:
# DB_USER=uniauth
# DB_PASSWORD=localdevpassword
# DB_NAME=uniauth
# JWT_SECRET=at-least-32-chars-random-string-here
# APP_ENV=development
```

- [ ] **Step 2: Start Docker Compose**

```bash
docker compose up --build -d
```

- [ ] **Step 3: Apply the schema**

Run existing table creation SQL files in dependency order, then the migration:

```bash
# From the project root, connect to the Docker DB:
PGPASSWORD=localdevpassword psql -h localhost -U uniauth -d uniauth \
  -f create_table_sql/sys_apps.sql \
  -f create_table_sql/sys_users.sql \
  -f create_table_sql/sys_permissions.sql \
  -f create_table_sql/sys_roles.sql \
  -f create_table_sql/sys_role_data_scopes.sql \
  -f create_table_sql/sys_role_permission_masks.sql \
  -f create_table_sql/sys_user_roles.sql \
  -f create_table_sql/sys_app_members.sql \
  -f create_table_sql/migration_totp_blacklist.sql
```

- [ ] **Step 4: Run setup_admin.go to create the admin user**

```bash
go run setup_admin.go
```

Follow the prompts to assign admin role to a user.

- [ ] **Step 5: Smoke test the login → TOTP flow**

```bash
# 1. Login — should return totp_setup_required
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your_user>","password":"<your_pass>"}' | jq .
# Expected: {"status":"totp_setup_required","pre_auth_token":"<jwt>"}

# 2. Get QR code (copy pre_auth_token from above)
curl -s http://localhost:8080/api/v1/auth/totp/setup \
  -H "Authorization: Bearer <pre_auth_token>" | jq .secret
# Expected: base32 secret string

# 3. Add the secret to Google Authenticator, get a 6-digit code, then enroll:
curl -s -X POST http://localhost:8080/api/v1/auth/totp/enroll \
  -H "Authorization: Bearer <pre_auth_token>" \
  -H "Content-Type: application/json" \
  -d '{"code":"<6_digit_code>"}' | jq .
# Expected: {"message":"TOTP enrollment successful","token":"<full_auth_token>"}

# 4. Second login — should now return totp_required
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your_user>","password":"<your_pass>"}' | jq .status
# Expected: "totp_required"
```

- [ ] **Step 6: Verify rate limiting**

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}'
done
```

Expected: first 10 return `401`, 11th and 12th return `429`.

- [ ] **Step 7: Commit**

```bash
git add .env.example  # do NOT commit .env
git commit -m "feat: complete UniAuth hardening — PostgreSQL migration, TOTP 2FA, security fixes"
```

---

## Supabase → Docker PostgreSQL Data Migration

Run these steps once after the Docker instance is running and schema is applied:

```bash
# 1. Export from Supabase (run from a machine that can reach Supabase)
pg_dump "$SUPABASE_DSN" \
  --no-owner --no-acl \
  --table=sys_apps \
  --table=sys_users \
  --table=sys_permissions \
  --table=sys_roles \
  --table=sys_role_data_scopes \
  --table=sys_role_permission_masks \
  --table=sys_user_roles \
  --table=sys_app_members \
  --table=sys_token_blacklist \
  > backup.sql

# 2. Import to new Docker PostgreSQL
PGPASSWORD=<new_db_password> psql \
  -h localhost -U uniauth -d uniauth \
  < backup.sql

# 3. Verify record counts match
psql "$SUPABASE_DSN" -c "SELECT COUNT(*) FROM sys_users;"
PGPASSWORD=<new_db_password> psql -h localhost -U uniauth -d uniauth \
  -c "SELECT COUNT(*) FROM sys_users;"
```

---

## Spec Coverage Check

| Spec requirement | Task |
|-----------------|------|
| PostgreSQL migration to Docker | Tasks 3, 12 |
| Configurable sslmode / timezone | Tasks 1, 2 |
| Startup validation for required env vars | Task 1 |
| JWT_SECRET required | Task 1 |
| TOTP columns on sys_users | Tasks 4, 5 |
| pre_auth_token (5-min JWT) | Task 6 |
| Login returns pre_auth_token + status | Task 9 |
| GET /auth/totp/setup | Task 8 |
| POST /auth/totp/enroll | Task 8 |
| POST /auth/totp/verify | Task 8 |
| POST /admin/users/:id/totp/reset | Tasks 8, 11 |
| PreAuthMiddleware | Task 7 |
| AuthMiddleware rejects pre_auth tokens | Task 7 |
| Admin permission check — bit 0 | Task 10a |
| Cookie Secure + SameSite=Strict | Task 9 |
| Login rate limiting (10/min) | Tasks 7, 11 |
| parseUint error handling | Task 10c |
| BitIndex overflow check | Task 10b |
| CORS middleware | Task 11 |
| Request size limit (4MB) | Task 11 |
| Token blacklist cleanup goroutine | Tasks 2, 11 |
| Token blacklist indexes | Task 4 |
| List pagination | Task 10d |
