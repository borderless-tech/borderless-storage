#!/usr/bin/env bash
#
# Test: Presigned URL security - expiry, tampered signatures, missing params
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Presigned URL Security"

# --- Test 1: Expired presigned URL ---
echo "-> Requesting presigned upload URL with short expiry..."
# Request presign with expires_in=1 (1 second)
RES=$(curl -fsS $HOST/presign \
    -H "authorization: Bearer $API_KEY" \
    -H "content-type: application/json" \
    -d '{"action": "upload", "expires_in": 1}')

UPLOAD_URL=$(echo "$RES" | jq -r '.url')

echo "-> Waiting for URL to expire..."
sleep 3

echo "-> Attempting upload with expired URL (should fail)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$UPLOAD_URL" --data-binary @"data/number-1")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Presign Security" "Expired presigned URL should have been rejected but got HTTP 200"
fi
echo "  Expired URL rejected with HTTP $HTTP_CODE"

# --- Test 2: Tampered signature ---
echo "-> Requesting valid presigned upload URL..."
UPLOAD_URL=$(presign_rq "upload")

# Tamper with the signature by replacing last 4 chars
TAMPERED_URL=$(echo "$UPLOAD_URL" | sed 's/.\{4\}$/XXXX/')

echo "-> Attempting upload with tampered signature (should fail)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TAMPERED_URL" --data-binary @"data/number-1")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Presign Security" "Tampered signature should have been rejected but got HTTP 200"
fi
echo "  Tampered signature rejected with HTTP $HTTP_CODE"

# --- Test 3: Tampered path (change blob_id but keep sig) ---
echo "-> Requesting presigned upload URL for specific blob..."
BLOB_ID=$(uuidgen)
UPLOAD_URL=$(presign_rq "upload" "$BLOB_ID")

# Replace the blob_id in the URL path with a different UUID
FAKE_BLOB=$(uuidgen)
TAMPERED_PATH_URL=$(echo "$UPLOAD_URL" | sed "s|$BLOB_ID|$FAKE_BLOB|g")

echo "-> Attempting upload with tampered path (should fail)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TAMPERED_PATH_URL" --data-binary @"data/number-1")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Presign Security" "Tampered path should have been rejected but got HTTP 200"
fi
echo "  Tampered path rejected with HTTP $HTTP_CODE"

# --- Test 4: Missing query parameters ---
echo "-> Testing URL with missing sig parameter..."
# Strip sig param from a valid URL
NO_SIG_URL=$(echo "$UPLOAD_URL" | sed 's/&sig=[^&]*//')

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$NO_SIG_URL" --data-binary @"data/number-1")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Presign Security" "URL without sig should have been rejected but got HTTP 200"
fi
echo "  Missing sig rejected with HTTP $HTTP_CODE"

echo "-> Testing URL with missing expires parameter..."
# Strip expires param
NO_EXPIRES_URL=$(echo "$UPLOAD_URL" | sed 's/expires=[^&]*&//')

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$NO_EXPIRES_URL" --data-binary @"data/number-1")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Presign Security" "URL without expires should have been rejected but got HTTP 200"
fi
echo "  Missing expires rejected with HTTP $HTTP_CODE"

test_success "Presigned URL Security"
