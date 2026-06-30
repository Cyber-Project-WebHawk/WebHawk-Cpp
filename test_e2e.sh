#!/usr/bin/env bash
# WebHawk — End-to-End Test Script
# Usage: bash test_e2e.sh
# Requires: curl, jq
# Run AFTER: docker compose up --build

set -euo pipefail

BASE="http://localhost:8080"
PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; ((PASS++)); }
fail() { echo "[FAIL] $1"; ((FAIL++)); }

assert_status() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" -eq "$expected" ]; then ok "$label (HTTP $actual)";
    else fail "$label (expected $expected, got $actual)"; fi
}

echo "=== WebHawk E2E Test Suite ==="
echo ""

# ── 1. Register admin user ───────────────────────────────────────────────────
echo "--- Auth ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}')
assert_status "POST /api/auth/register (first user → admin)" 201 "$STATUS"

# ── 2. Duplicate registration ────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}')
assert_status "POST /api/auth/register (duplicate → 409)" 409 "$STATUS"

# ── 3. Login ─────────────────────────────────────────────────────────────────
LOGIN=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}')
ACCESS=$(echo "$LOGIN" | jq -r '.accessToken')
REFRESH=$(echo "$LOGIN" | jq -r '.refreshToken')
ROLE=$(echo "$LOGIN" | jq -r '.user.role')

if [ "$ACCESS" != "null" ] && [ -n "$ACCESS" ]; then ok "POST /api/auth/login (got token)";
else fail "POST /api/auth/login (no token)"; fi

if [ "$ROLE" = "admin" ]; then ok "First user has admin role";
else fail "First user role: expected admin, got $ROLE"; fi

# ── 4. GET /api/auth/me ──────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/me" \
  -H "Authorization: Bearer $ACCESS")
assert_status "GET /api/auth/me (with token)" 200 "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/me")
assert_status "GET /api/auth/me (no token → 401)" 401 "$STATUS"

# ── 5. Wrong password → 401 ──────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"WrongPass1!"}')
assert_status "POST /api/auth/login (wrong password → 401)" 401 "$STATUS"

# ── 6. Token refresh ─────────────────────────────────────────────────────────
REFRESHED=$(curl -s -X POST "$BASE/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")
NEW_ACCESS=$(echo "$REFRESHED" | jq -r '.accessToken')
if [ "$NEW_ACCESS" != "null" ] && [ -n "$NEW_ACCESS" ]; then ok "POST /api/auth/refresh";
else fail "POST /api/auth/refresh (no new token)"; fi

echo ""
echo "--- Backend Registration ---"

# ── 7. Register backend (admin only) ─────────────────────────────────────────
REG=$(curl -s -X POST "$BASE/api/backends/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -d '{"serviceName":"vuln-backend","targetUrl":"http://vulnerable-backend:9090"}')
API_KEY=$(echo "$REG" | jq -r '.apiKey')

if [ "$API_KEY" != "null" ] && [ ${#API_KEY} -eq 64 ]; then ok "POST /api/backends/register (64-char key)";
else fail "POST /api/backends/register (got: $API_KEY)"; fi

# ── 8. Invalid targetUrl ─────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/backends/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -d '{"serviceName":"bad","targetUrl":"ftp://evil.host"}')
assert_status "POST /api/backends/register (bad URL scheme → 400)" 400 "$STATUS"

# ── 9. List backends ─────────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/backends" \
  -H "Authorization: Bearer $ACCESS")
assert_status "GET /api/backends" 200 "$STATUS"

# ── 10. Non-admin cannot access backends ─────────────────────────────────────
REG2=$(curl -s -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.local","password":"User1234!"}')
LOGIN2=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.local","password":"User1234!"}')
USER_TOKEN=$(echo "$LOGIN2" | jq -r '.accessToken')

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/backends" \
  -H "Authorization: Bearer $USER_TOKEN")
assert_status "GET /api/backends (non-admin → 403)" 403 "$STATUS"

echo ""
echo "--- Proxy / Security Engine ---"

# ── 11. Missing API key ───────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/proxy/vuln/ping")
assert_status "GET /proxy/vuln/ping (no API key → 401)" 401 "$STATUS"

# ── 12. Unknown API key ───────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/proxy/vuln/ping" \
  -H "X-WebHawk-API-Key: 0000000000000000000000000000000000000000000000000000000000000000")
assert_status "GET /proxy/vuln/ping (bad key → 404)" 404 "$STATUS"

# ── 13. Safe request forwarded ────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/proxy/vuln/ping" \
  -H "X-WebHawk-API-Key: $API_KEY")
assert_status "GET /proxy/vuln/ping (safe → forwarded, 200)" 200 "$STATUS"

# ── 14. SQLi blocked ─────────────────────────────────────────────────────────
BODY=$(curl -s -X POST "$BASE/proxy/vuln/login" \
  -H "X-WebHawk-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/proxy/vuln/login" \
  -H "X-WebHawk-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}')
ATTACK=$(echo "$BODY" | jq -r '.attack_type // empty')

assert_status "POST /proxy/vuln/login (SQLi → 403)" 403 "$STATUS"
if [ "$ATTACK" = "SQLi" ]; then ok "SQLi attack_type in response";
else fail "SQLi attack_type missing (got: $ATTACK)"; fi

# ── 15. XSS blocked ──────────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/proxy/vuln/search?q=%3Cscript%3Ealert(1)%3C/script%3E" \
  -H "X-WebHawk-API-Key: $API_KEY")
assert_status "GET /proxy/vuln/search (XSS → 403)" 403 "$STATUS"

# ── 16. DELETE nonexistent backend → 404 ────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/api/backends/99999" \
  -H "Authorization: Bearer $ACCESS")
assert_status "DELETE /api/backends/99999 (not found → 404)" 404 "$STATUS"

# ── 17. Logout ───────────────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/logout" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")
assert_status "POST /api/auth/logout" 200 "$STATUS"

# Revoked token must no longer work
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")
assert_status "POST /api/auth/refresh (revoked token → 401)" 401 "$STATUS"

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
