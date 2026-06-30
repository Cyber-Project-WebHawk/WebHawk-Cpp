#!/usr/bin/env bash
# WebHawk — End-to-End Test Script
# Usage: bash test_e2e.sh
# Requires: curl, jq
# Run AFTER: docker compose up --build

set -uo pipefail

BASE="${WEBHAWK_BASE:-http://localhost:8080}"
PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; ((PASS+=1)); }
fail() { echo "[FAIL] $1"; ((FAIL+=1)); }

assert_status() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" -eq "$expected" ]; then ok "$label (HTTP $actual)";
    else fail "$label (expected $expected, got $actual)"; fi
}

# Runs curl and returns the HTTP status code.
# On connection error or timeout, prints "000" so the test fails gracefully
# instead of killing the script (curl exits non-zero on timeout/error).
curl_status() {
    # curl already writes "000" to stdout on timeout/error before exiting non-zero,
    # so || true is enough — || echo "000" would double the output.
    curl --connect-timeout 5 --max-time 10 -s -o /dev/null -w "%{http_code}" "$@" || true
}

echo "=== WebHawk E2E Test Suite ==="
echo ""

# ── 1. Register admin user ───────────────────────────────────────────────────
echo "--- Auth ---"
STATUS=$(curl_status -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}')
# 201 = fresh DB; 409 = user already exists from a previous run — both are fine
if [ "$STATUS" -eq 201 ]; then ok "POST /api/auth/register (first user → admin, HTTP 201)";
elif [ "$STATUS" -eq 409 ]; then ok "POST /api/auth/register (user exists from prior run, HTTP 409 — skipping)";
else fail "POST /api/auth/register (expected 201 or 409, got $STATUS)"; fi

# ── 2. Duplicate registration ────────────────────────────────────────────────
STATUS=$(curl_status -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}')
assert_status "POST /api/auth/register (duplicate → 409)" 409 "$STATUS"

# ── 3. Login ─────────────────────────────────────────────────────────────────
LOGIN=$(curl --connect-timeout 5 --max-time 10 -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"Admin123!"}' || echo '{}')
ACCESS=$(echo "$LOGIN" | jq -r '.accessToken // empty')
REFRESH=$(echo "$LOGIN" | jq -r '.refreshToken // empty')
ROLE=$(echo "$LOGIN" | jq -r '.user.role // empty')

if [ -n "$ACCESS" ]; then ok "POST /api/auth/login (got token)";
else fail "POST /api/auth/login (no token)"; fi

if [ "$ROLE" = "admin" ]; then ok "First user has admin role";
else fail "First user role: expected admin, got $ROLE"; fi

# ── 4. GET /api/auth/me ──────────────────────────────────────────────────────
STATUS=$(curl_status "$BASE/api/auth/me" \
  -H "Authorization: Bearer $ACCESS")
assert_status "GET /api/auth/me (with token)" 200 "$STATUS"

STATUS=$(curl_status "$BASE/api/auth/me")
assert_status "GET /api/auth/me (no token → 401)" 401 "$STATUS"

# ── 5. Wrong password → 401 ──────────────────────────────────────────────────
STATUS=$(curl_status -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"WrongPass1!"}')
assert_status "POST /api/auth/login (wrong password → 401)" 401 "$STATUS"

# ── 6. Token refresh ─────────────────────────────────────────────────────────
REFRESHED=$(curl --connect-timeout 5 --max-time 10 -s -X POST "$BASE/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}" || echo '{}')
NEW_ACCESS=$(echo "$REFRESHED" | jq -r '.accessToken // empty')
if [ -n "$NEW_ACCESS" ]; then ok "POST /api/auth/refresh";
else fail "POST /api/auth/refresh (no new token)"; fi

echo ""
echo "--- Backend Registration ---"

# ── 7. Register backend (admin only) ─────────────────────────────────────────
REG=$(curl --connect-timeout 5 --max-time 10 -s -X POST "$BASE/api/backends/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -d '{"serviceName":"vuln-backend","targetUrl":"http://vulnerable-backend:9090"}' || echo '{}')
API_KEY=$(echo "$REG" | jq -r '.apiKey // empty')

if [ -n "$API_KEY" ] && [ ${#API_KEY} -eq 64 ]; then ok "POST /api/backends/register (64-char key)";
else fail "POST /api/backends/register (got: $API_KEY)"; fi

# ── 8. Invalid targetUrl ─────────────────────────────────────────────────────
STATUS=$(curl_status -X POST "$BASE/api/backends/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -d '{"serviceName":"bad","targetUrl":"ftp://evil.host"}')
assert_status "POST /api/backends/register (bad URL scheme → 400)" 400 "$STATUS"

# ── 9. List backends ─────────────────────────────────────────────────────────
STATUS=$(curl_status "$BASE/api/backends" \
  -H "Authorization: Bearer $ACCESS")
assert_status "GET /api/backends" 200 "$STATUS"

# ── 10. Non-admin cannot access backends ─────────────────────────────────────
REG_STATUS=$(curl_status -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.local","password":"User1234!"}')
if [ "$REG_STATUS" -eq 201 ]; then ok "POST /api/auth/register (non-admin user, HTTP 201)";
elif [ "$REG_STATUS" -eq 409 ]; then ok "POST /api/auth/register (non-admin user exists from prior run, HTTP 409 — skipping)";
else fail "POST /api/auth/register non-admin (expected 201 or 409, got $REG_STATUS)"; fi

LOGIN2=$(curl --connect-timeout 5 --max-time 10 -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.local","password":"User1234!"}' || echo '{}')
USER_TOKEN=$(echo "$LOGIN2" | jq -r '.accessToken // empty')

STATUS=$(curl_status "$BASE/api/backends" \
  -H "Authorization: Bearer $USER_TOKEN")
assert_status "GET /api/backends (non-admin → 403)" 403 "$STATUS"

echo ""
echo "--- Proxy / Security Engine ---"

# ── 11. Missing API key ───────────────────────────────────────────────────────
STATUS=$(curl_status "$BASE/proxy/vuln/ping")
assert_status "GET /proxy/vuln/ping (no API key → 401)" 401 "$STATUS"

# ── 12. Unknown API key ───────────────────────────────────────────────────────
STATUS=$(curl_status "$BASE/proxy/vuln/ping" \
  -H "X-WebHawk-API-Key: 0000000000000000000000000000000000000000000000000000000000000000")
assert_status "GET /proxy/vuln/ping (bad key → 404)" 404 "$STATUS"

# ── 13. Safe request forwarded ────────────────────────────────────────────────
STATUS=$(curl_status "$BASE/proxy/vuln/ping" \
  -H "X-WebHawk-API-Key: $API_KEY")
assert_status "GET /proxy/vuln/ping (safe → forwarded, 200)" 200 "$STATUS"

# ── 14. SQLi blocked ─────────────────────────────────────────────────────────
BODY=$(curl --connect-timeout 5 --max-time 10 -s -X POST "$BASE/proxy/vuln/login" \
  -H "X-WebHawk-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}' || echo '{}')
STATUS=$(curl_status -X POST "$BASE/proxy/vuln/login" \
  -H "X-WebHawk-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}')
ATTACK=$(echo "$BODY" | jq -r '.attack_type // empty')

assert_status "POST /proxy/vuln/login (SQLi → 403)" 403 "$STATUS"
if [ "$ATTACK" = "SQLi" ]; then ok "SQLi attack_type in response";
else fail "SQLi attack_type missing (got: $ATTACK)"; fi

# ── 15. XSS blocked ──────────────────────────────────────────────────────────
STATUS=$(curl_status \
  "$BASE/proxy/vuln/search?q=%3Cscript%3Ealert(1)%3C/script%3E" \
  -H "X-WebHawk-API-Key: $API_KEY")
assert_status "GET /proxy/vuln/search (XSS → 403)" 403 "$STATUS"

# ── 16. DELETE nonexistent backend → 404 ────────────────────────────────────
STATUS=$(curl_status -X DELETE "$BASE/api/backends/99999" \
  -H "Authorization: Bearer $ACCESS")
assert_status "DELETE /api/backends/99999 (not found → 404)" 404 "$STATUS"

# ── 17. Logout ───────────────────────────────────────────────────────────────
STATUS=$(curl_status -X POST "$BASE/api/auth/logout" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")
assert_status "POST /api/auth/logout" 200 "$STATUS"

# Revoked token must no longer work
STATUS=$(curl_status -X POST "$BASE/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")
assert_status "POST /api/auth/refresh (revoked token → 401)" 401 "$STATUS"

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
