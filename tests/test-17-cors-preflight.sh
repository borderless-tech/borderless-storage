#!/usr/bin/env bash
#
# Test: CORS preflight - OPTIONS requests return proper CORS headers
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "CORS Preflight"

echo "-> Sending OPTIONS preflight request..."
RESPONSE=$(curl -s -i -X OPTIONS "$HOST/presign" \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: authorization,content-type" 2>&1)

# Check for CORS headers (case-insensitive)
echo "-> Checking for access-control-allow-methods header..."
ALLOW_METHODS=$(echo "$RESPONSE" | grep -i "^access-control-allow-methods:" | head -1)

if [[ -z "$ALLOW_METHODS" ]]; then
    test_failed "CORS" "Missing access-control-allow-methods header in OPTIONS response"
fi
echo "  $ALLOW_METHODS"

# Verify key methods are allowed
for METHOD in GET POST PUT DELETE; do
    if ! echo "$ALLOW_METHODS" | grep -qi "$METHOD"; then
        test_failed "CORS" "Method $METHOD not found in allowed methods"
    fi
done
echo "  All required methods (GET, POST, PUT, DELETE) present"

echo "-> Checking for access-control-allow-origin header..."
ALLOW_ORIGIN=$(echo "$RESPONSE" | grep -i "^access-control-allow-origin:" | head -1)

if [[ -z "$ALLOW_ORIGIN" ]]; then
    test_failed "CORS" "Missing access-control-allow-origin header in OPTIONS response"
fi
echo "  $ALLOW_ORIGIN"

test_success "CORS Preflight"
