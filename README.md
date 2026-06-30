# WebHawk — Security Middleware SaaS

A C++ WAF (Web Application Firewall) middleware that sits in front of registered backends, scans every proxied request for SQL injection, XSS, and rate-limit abuse, and blocks malicious traffic before it reaches the target service.

Built with **Drogon** (async HTTP), **PostgreSQL**, and **Redis**, packaged with **Docker Compose**.

---

## Architecture

Every feature follows **Route → Service → Repository**:

```
Route        HTTP only — parse request, call Service, return response
Service      Business logic — no HTTP, no raw SQL
Repository   Database queries only — returns domain objects
```

**Request flow (proxy):**

```
Client
  → Middleware /proxy/*  (X-WebHawk-API-Key)
    → BackendRepository  (lookup target URL by API key)
    → SecurityClient     (POST /api/security/scan)
      → Security Engine  (RateLimit → SQLi → XSS)
    → if safe: forward to registered backend
    → if unsafe: 403 Blocked by WebHawk
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| **middleware** | 8080 | Auth API, backend registration, main proxy |
| **security-engine** | 8081 | SQLi, XSS, and rate-limit detection |
| **vulnerable-backend** | 9090 | Intentionally vulnerable test server |
| **postgres** | 5432 | Primary database |
| **redis** | 6379 | Rate-limit counters |

---

## Running the Project

### Prerequisites

| Requirement | Minimum version | Notes |
|-------------|-----------------|-------|
| Docker | 24+ | `docker --version` |
| Docker Compose v2 | included with Docker Desktop | use `docker compose` (with a space), not `docker-compose` |
| Free RAM | 4 GB | Drogon is compiled from source inside the containers — builds are heavy |
| Free disk | 3 GB | image layers + postgres data volume |

> **First build takes 10–20 minutes.** Subsequent builds reuse Docker layer cache and are much faster.

---

### Step 1 — Configure environment

```bash
cp .env.example .env
```

Open `.env` and fill in the two required values:

```
DB_PASSWORD=choose_a_strong_password
JWT_SECRET=at_least_32_random_characters_here
```

`JWT_SECRET` is used to sign and verify every access token. Use any long random string.

---

### Step 2 — Build and start all services

```bash
docker compose up --build
```

Docker Compose starts everything in dependency order:

```
postgres  ──┐
redis     ──┼──▶  security-engine  ──▶  middleware
             └──▶  vulnerable-backend
```

postgres and redis must pass their health checks before the app services start.

---

### Step 3 — Verify all services are up

Watch the logs for these lines:

| Service | Log line that means "ready" |
|---------|-----------------------------|
| postgres | `database system is ready to accept connections` |
| redis | `Ready to accept connections tcp` |
| security-engine | `Listening on 0.0.0.0:8081` |
| middleware | `Listening on 0.0.0.0:8080` |
| vulnerable-backend | `Listening on 0.0.0.0:9090` |

Quick smoke test with curl:

```bash
# Should return 400 (bad request), NOT 502 (gateway error)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/auth/register

# Should return 200
curl -s http://localhost:9090/vuln/ping
```

---

### Useful commands

| Goal | Command |
|------|---------|
| Start (no rebuild) | `docker compose up` |
| Rebuild after code change | `docker compose up --build` |
| Run in background | `docker compose up -d` |
| View logs | `docker compose logs -f` |
| Stop (keep data) | `docker compose down` |
| Stop and wipe database | `docker compose down -v` |
| Rebuild one service only | `docker compose up --build middleware` |

---

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `DB_PASSWORD` | postgres, middleware, security-engine, vulnerable-backend | PostgreSQL password |
| `JWT_SECRET` | middleware | Secret for signing access tokens |
| `SECURITY_ENGINE_URL` | middleware | Base URL of the security engine (set automatically in Docker to `http://security-engine:8081`) |
| `DB_HOST`, `DB_NAME`, `DB_USER` | all app services | Database connection (defaults to `webhawk` / `webhawk`) |
| `REDIS_HOST` | security-engine | Redis host for rate limiting |

---

## API Reference

### Authentication (`middleware:8080`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | — | Register a new user (`email`, `password`) |
| POST | `/api/auth/login` | — | Login; returns access + refresh tokens |
| POST | `/api/auth/refresh` | — | Exchange a refresh token for a new token pair |
| POST | `/api/auth/logout` | Bearer | Revoke a refresh token |
| GET | `/api/auth/me` | Bearer | Return the current user's profile |

The **first registered user** is automatically assigned the `admin` role. All subsequent users get `user`.

Protected routes require `Authorization: Bearer <accessToken>`.

### Backend Registration (`middleware:8080`) — Admin only

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/backends/register` | Admin Bearer | Register a backend; returns a 64-char hex API key |
| GET | `/api/backends` | Admin Bearer | List registered backends (API keys omitted) |
| DELETE | `/api/backends/{id}` | Admin Bearer | Soft-deactivate a backend |

Request body for register:

```json
{ "serviceName": "vuln-backend", "targetUrl": "http://vulnerable-backend:9090" }
```

### Proxy (`middleware:8080`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/POST/PUT/DELETE/PATCH | `/proxy/{path}` | `X-WebHawk-API-Key` | Scan and forward to the registered backend |

The proxy strips the `/proxy` prefix before forwarding. For example, a request to `/proxy/vuln/search?q=test` is forwarded to `{targetUrl}/vuln/search?q=test`.

The `X-WebHawk-API-Key` header is removed before the request reaches the backend.

**Responses:**

| Status | Meaning |
|--------|---------|
| 401 | Missing API key |
| 403 | Blocked by WebHawk (`attack_type`: SQLi, XSS, RateLimit) |
| 404 | Unknown or deactivated API key |
| 502 | Backend unreachable |
| 503 | Security engine unavailable (fail closed) |

### Security Engine (`security-engine:8081`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/security/scan` | Scan a request payload (called internally by middleware) |

**Request:**

```json
{
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/vuln/login",
  "query_params": { "q": "..." },
  "headers": { "User-Agent": "..." },
  "body": "username=admin'--&password=x"
}
```

**Response:**

```json
{ "safe": false, "attack_type": "SQLi", "detail": "OR pattern in body" }
```

Checks run in order: **Rate Limit** (Redis) → **SQL Injection** → **XSS**. Blocked requests are logged to `security_logs`.

---

## Security Engine — Detection Details

The security engine runs three checks on every request **in sequence**. The first check that fires returns immediately — the rest are skipped.

### 1. Rate Limiting (Redis)

Every client IP is tracked with a Redis counter (`rate:<ip>`). The counter auto-expires after **60 seconds**.

| Threshold | Action |
|-----------|--------|
| ≤ 100 requests / 60 s | Allowed — scan continues |
| > 100 requests / 60 s | Blocked — `attack_type: RateLimit` |

The counter is incremented with `INCR` and the TTL is set only on the **first** request of each window, so the window is always 60 seconds from the first hit. The Redis call is **fully asynchronous** — the Drogon event loop is never blocked.

### 2. SQL Injection Detection

The following parts of every request are scanned:

| Location | Example |
|----------|---------|
| URL path | `/search/users'--` |
| Query parameters | `?id=1 OR 1=1` |
| Request body | `{"user":"admin'; DROP TABLE users--"}` |
| HTTP headers | `User-Agent: ' UNION SELECT * FROM users--` |

Detected pattern categories:

| Category | Patterns |
|----------|----------|
| Comment syntax | `--`, `;--`, `/*`, `*/` |
| Tautologies | `1=1`, `or 1=1`, `' or '` |
| DML / DDL keywords | `union select`, `select `, `insert `, `update `, `delete `, `drop `, `create `, `alter ` |
| Stored procedures | `exec(`, `execute(`, `xp_` |
| Type functions | `cast(`, `convert(`, `char(`, `nchar(`, `varchar(` |
| Time-based blind | `sleep(`, `waitfor delay`, `benchmark(` |
| Information disclosure | `information_schema`, `sys.tables`, `@@version` |

All comparisons are case-insensitive (`toLower` before matching).

### 3. XSS Detection

The same four locations are scanned (path, query params, body, headers).

| Category | Patterns |
|----------|----------|
| Script tags | `<script`, `</script>` |
| Event handlers | `onload=`, `onerror=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`, `onkeydown=`, `onkeyup=`, `onsubmit=` |
| Dangerous tags | `<iframe`, `<img`, `<svg`, `<body`, `<input`, `<link`, `<meta` |
| Dangerous URIs | `javascript:`, `vbscript:`, `src=javascript`, `href=javascript`, `url(javascript` |
| DOM manipulation | `document.cookie`, `document.write`, `window.location`, `eval(`, `expression(` |
| Encoded payloads | `&#`, `%3cscript`, `%3c` |
| Other | `alert(` |

### Attack Logging

Every blocked request is written to `security_logs`:

| Column | Value |
|--------|-------|
| `ip_address` | Client IP from the middleware |
| `method` | HTTP method (GET, POST, …) |
| `endpoint` | Request path |
| `attack_type` | `SQLi`, `XSS`, or `RateLimit` |
| `was_blocked` | Always `TRUE` for blocked requests |
| `raw_payload` | Full request body (for forensics) |
| `detected_at` | Server timestamp |

---

### Vulnerable Backend (`vulnerable-backend:9090`) — Testing only

| Method | Path | Vulnerability |
|--------|------|---------------|
| POST | `/vuln/login` | SQL injection (raw string concatenation in SQL) |
| GET | `/vuln/search?q=` | Reflected XSS (query param echoed into HTML) |
| GET | `/vuln/admin` | No authentication on sensitive admin data |
| GET | `/vuln/ping` | Safe health check |

---

## Testing

### Running the Test Suite

`test_e2e.sh` is a self-contained bash script that runs **21 automated checks** against the live running system. It uses `curl` to make HTTP requests and `jq` to parse JSON responses.

No extra tools needed — `curl` and `jq` are installed automatically inside a dedicated Docker container.

```bash
# 1. Start all services (first time — builds everything)
docker compose up --build -d

# 2. Wait ~30 seconds for all services to initialise, then run the tests:
docker compose --profile test run --rm tester
```

To run tests on subsequent runs (no rebuild needed):

```bash
docker compose up -d
docker compose --profile test run --rm tester
```

You can still run the script directly on your machine if you have `jq` installed:

```bash
bash test_e2e.sh
```

When all tests pass the output looks like this:

```
=== WebHawk E2E Test Suite ===

--- Auth ---
[PASS] POST /api/auth/register (first user → admin) (HTTP 201)
[PASS] POST /api/auth/register (duplicate → 409) (HTTP 409)
[PASS] POST /api/auth/login (got token)
[PASS] First user has admin role
[PASS] GET /api/auth/me (with token) (HTTP 200)
[PASS] GET /api/auth/me (no token → 401) (HTTP 401)
[PASS] POST /api/auth/login (wrong password → 401) (HTTP 401)
[PASS] POST /api/auth/refresh (HTTP 200)

--- Backend Registration ---
[PASS] POST /api/backends/register (64-char key)
[PASS] POST /api/backends/register (bad URL scheme → 400) (HTTP 400)
[PASS] GET /api/backends (HTTP 200)
[PASS] GET /api/backends (non-admin → 403) (HTTP 403)

--- Proxy / Security Engine ---
[PASS] GET /proxy/vuln/ping (no API key → 401) (HTTP 401)
[PASS] GET /proxy/vuln/ping (bad key → 404) (HTTP 404)
[PASS] GET /proxy/vuln/ping (safe → forwarded, 200) (HTTP 200)
[PASS] POST /proxy/vuln/login (SQLi → 403) (HTTP 403)
[PASS] SQLi attack_type in response
[PASS] GET /proxy/vuln/search (XSS → 403) (HTTP 403)
[PASS] DELETE /api/backends/99999 (not found → 404) (HTTP 404)
[PASS] POST /api/auth/logout (HTTP 200)
[PASS] POST /api/auth/refresh (revoked token → 401) (HTTP 401)

==============================
Results: 21 passed, 0 failed
==============================
```

The script exits with code `0` if all tests pass, or `1` if any test fails (`set -euo pipefail` is set, so it also stops immediately on an unexpected error).

---

### What Each Test Group Covers

**Auth (8 checks)**

| Check | What it verifies |
|-------|-----------------|
| Register → 201 | User creation works, password is stored (hashed) |
| Duplicate → 409 | Unique email constraint enforced |
| Login → token | JWT access + refresh tokens are issued |
| First user → admin | Role auto-assignment logic works |
| `/me` with token → 200 | `JwtAuthFilter` accepts valid tokens |
| `/me` no token → 401 | `JwtAuthFilter` rejects missing tokens |
| Wrong password → 401 | Password verification (Argon2id) works |
| Refresh → new token | Refresh token rotation works |

**Backend Registration (4 checks)**

| Check | What it verifies |
|-------|-----------------|
| Register backend → 64-char key | API key generator produces a valid 64-char hex key |
| Bad URL scheme → 400 | Input validation rejects non-http/https URLs |
| List backends → 200 | `GET /api/backends` returns the registered entry |
| Non-admin → 403 | `AdminOnlyFilter` blocks regular users |

**Proxy / Security Engine (9 checks)**

| Check | What it verifies |
|-------|-----------------|
| No API key → 401 | Proxy enforces the `X-WebHawk-API-Key` header |
| Bad key → 404 | Unknown API keys are rejected |
| Safe request → 200 | Clean traffic is forwarded to the backend |
| SQLi payload → 403 | Security engine detects `admin'--` in request body |
| Response has `attack_type: SQLi` | Response body includes the attack classification |
| XSS payload → 403 | Security engine detects `%3Cscript%3E` in query params |
| Delete nonexistent → 404 | Backend deactivation returns 404 for unknown IDs |
| Logout → 200 | Refresh token is revoked in the database |
| Revoked token → 401 | Revoked refresh token is rejected on next use |

---

### What It Means in a CI/CD Pipeline

The script is designed to run as a pipeline stage after `docker compose up`. Because it exits `0` on success and `1` on failure, any CI system (GitHub Actions, GitLab CI, Jenkins) can use the exit code to pass or fail the build automatically.

**Example GitHub Actions workflow:**

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create .env
        run: |
          echo "DB_PASSWORD=testpass" >> .env
          echo "JWT_SECRET=test-secret-for-ci-only-not-for-prod" >> .env

      - name: Start services
        run: docker compose up --build -d

      - name: Wait for services to be ready
        run: sleep 30

      - name: Run E2E tests
        run: docker compose --profile test run --rm tester
```

**When the pipeline passes:** all 21 assertions returned the expected HTTP status codes and JSON fields. The system is working end-to-end — auth, proxy, and attack detection are all functional.

**When the pipeline fails:** a `[FAIL]` line in the output shows exactly which check broke and what status code was actually returned, making it easy to pinpoint the failing component.

---

## Project Structure

```
webhawk/
├── middleware/                  # Main proxy + auth + registration
│   ├── main.cc
│   └── src/
│       ├── routes/              # AuthRoute, RegistrationRoute, ProxyRoute
│       ├── services/            # AuthService, RegistrationService, ProxyService, SecurityClient
│       ├── repositories/        # UserRepository, SessionRepository, BackendRepository
│       ├── filters/             # JwtAuthFilter, AdminOnlyFilter
│       └── utils/               # ApiKeyGenerator, JwtHelper, PasswordHasher
├── security-engine/             # Attack detection service
│   └── src/
│       ├── routes/              # ScanRoute
│       ├── services/            # SqlInjectionDetector, XssDetector, RateLimiter
│       └── repositories/        # SecurityLogRepository
├── vulnerable-backend/          # Intentionally vulnerable test server
│   └── src/routes/              # VulnLoginRoute, VulnSearchRoute, VulnAdminRoute
├── db/init.sql                  # PostgreSQL schema
└── docker-compose.yml
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | C++17 |
| HTTP framework | Drogon (async) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Auth | JWT (jwt-cpp) + Argon2id (libsodium) |
| Containers | Docker + Docker Compose |

---

## Team

| Student | Responsibility |
|---------|----------------|
| Student 1 | User management — JWT auth, sessions, admin roles |
| Student 2 | Security engine — SQLi, XSS, rate limiting |
| Student 3 | Infrastructure — proxy, backend registration, Docker |
