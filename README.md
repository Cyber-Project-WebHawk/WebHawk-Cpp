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

## Quick Start

```bash
cp .env.example .env
# Edit .env — set DB_PASSWORD and JWT_SECRET

docker compose up --build
```

All five services start together. Postgres is initialised from `db/init.sql` on first run.

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

### Vulnerable Backend (`vulnerable-backend:9090`) — Testing only

| Method | Path | Vulnerability |
|--------|------|---------------|
| POST | `/vuln/login` | SQL injection (raw string concatenation in SQL) |
| GET | `/vuln/search?q=` | Reflected XSS (query param echoed into HTML) |
| GET | `/vuln/admin` | No authentication on sensitive admin data |
| GET | `/vuln/ping` | Safe health check |

---

## End-to-End Test

```bash
# 1. Register the first user (becomes admin)
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@webhawk.local","password":"SecurePass123!"}'

# 2. Login and save the access token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@webhawk.local","password":"SecurePass123!"}'

# 3. Register the vulnerable backend
curl -X POST http://localhost:8080/api/backends/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <accessToken>" \
  -d '{"serviceName":"vuln-backend","targetUrl":"http://vulnerable-backend:9090"}'
# → save the returned apiKey

# 4. Safe request — forwarded to backend
curl http://localhost:8080/proxy/vuln/ping \
  -H "X-WebHawk-API-Key: <apiKey>"

# 5. SQLi attempt — blocked by WebHawk
curl -X POST http://localhost:8080/proxy/vuln/login \
  -H "X-WebHawk-API-Key: <apiKey>" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}'
# → 403 { "error": "Blocked by WebHawk", "attack_type": "SQLi" }

# 6. XSS attempt — blocked by WebHawk
curl "http://localhost:8080/proxy/vuln/search?q=<script>alert(1)</script>" \
  -H "X-WebHawk-API-Key: <apiKey>"
# → 403 { "error": "Blocked by WebHawk", "attack_type": "XSS" }
```

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
