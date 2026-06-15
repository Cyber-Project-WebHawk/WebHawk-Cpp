# WebHawk — Security Middleware SaaS

A WAF (Web Application Firewall) middleware that intercepts backend requests and blocks SQLi, XSS, and Rate Limiting attacks in real time.

## Quick Start

```bash
cp .env.example .env
# Edit .env and set a real DB_PASSWORD

docker compose up --build
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| middleware | 8080 | Main proxy + registration API |
| vulnerable-backend | 9090 | Intentionally vulnerable test server |
| postgres | 5432 | Database |
| redis | 6379 | Rate limiting counters |

## Endpoints (Student 3)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/backends/register` | Register a backend, get API key |
| GET | `/api/backends` | List registered backends |
| DELETE | `/api/backends/{id}` | Deactivate a backend |
| ANY | `/proxy/*` | Main proxy — all requests go here |

## Team
- Student 1 — User Management (JWT, sessions)
- Student 2 — Security Engine (SQLi, XSS, Rate Limiting detection)
- Student 3 — Infrastructure (this repo, proxy, Docker)
