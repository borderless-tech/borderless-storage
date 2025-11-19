#!/usr/bin/env bash
#
# Test: Verify authentication is required for admin endpoints
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Authentication"

echo "→ Testing presign without API key (should fail)..."
if curl -fsS "$HOST/presign" \
    -H "content-type: application/json" \
    -d '{"action": "upload"}' > /dev/null 2>&1; then
    test_failed "Authentication" "Presign without API key should have failed"
fi
echo "  ✓ Presign requires API key"

echo "→ Testing presign with wrong API key (should fail)..."
if curl -fsS "$HOST/presign" \
    -H "authorization: Bearer wrong-key" \
    -H "content-type: application/json" \
    -d '{"action": "upload"}' > /dev/null 2>&1; then
    test_failed "Authentication" "Presign with wrong API key should have failed"
fi
echo "  ✓ Wrong API key rejected"

echo "→ Testing admin/stats without API key (should fail)..."
if curl -fsS "$HOST/admin/stats" > /dev/null 2>&1; then
    test_failed "Authentication" "Admin stats without API key should have failed"
fi
echo "  ✓ Admin endpoints require API key"

echo "→ Testing presign with correct API key (should succeed)..."
RES=$(curl -fsS "$HOST/presign" \
    -H "authorization: Bearer $API_KEY" \
    -H "content-type: application/json" \
    -d '{"action": "upload"}')

if [[ $(echo "$RES" | jq -r '.success') != "true" ]]; then
    test_failed "Authentication" "Presign with correct API key failed"
fi
echo "  ✓ Correct API key accepted"

test_success "Authentication"
