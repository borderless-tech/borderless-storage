#!/usr/bin/env bash
#
# Test: Request size limits - oversized presign request rejected
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Request Size Limits"

# --- Test 1: Oversized presign request (> 10 KiB default) ---
echo "-> Generating oversized presign request body (~15 KiB)..."
# Create a JSON payload with a very long field to exceed 10 KiB
PADDING=$(python3 -c "print('A' * 15000)" 2>/dev/null || printf 'A%.0s' $(seq 1 15000))
OVERSIZED_BODY='{"action": "upload", "padding": "'"$PADDING"'"}'

echo "  Payload size: $(echo -n "$OVERSIZED_BODY" | wc -c) bytes"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/presign" \
    -H "authorization: Bearer $API_KEY" \
    -H "content-type: application/json" \
    -d "$OVERSIZED_BODY")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Request Limits" "Oversized presign request should have been rejected but got HTTP 200"
fi
echo "  Oversized presign request rejected with HTTP $HTTP_CODE"

# --- Test 2: Normal-sized presign request still works ---
echo "-> Verifying normal presign request still works..."
RES=$(curl -fsS "$HOST/presign" \
    -H "authorization: Bearer $API_KEY" \
    -H "content-type: application/json" \
    -d '{"action": "upload"}')

if [[ $(echo "$RES" | jq -r '.success') != "true" ]]; then
    test_failed "Request Limits" "Normal presign request should have succeeded"
fi
echo "  Normal presign request accepted"

test_success "Request Size Limits"
