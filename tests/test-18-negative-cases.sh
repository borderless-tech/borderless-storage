#!/usr/bin/env bash
#
# Test: Negative cases and edge cases - 404s, zero-byte files, default metadata
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Negative Cases and Edge Cases"

# --- Test 1: Download non-existent blob ---
echo "-> Requesting download URL for non-existent blob..."
FAKE_BLOB=$(uuidgen)
DOWNLOAD_URL=$(presign_rq "download" "$FAKE_BLOB")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DOWNLOAD_URL")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Negative Cases" "Download of non-existent blob should return 404, got 200"
fi
echo "  Non-existent blob download returned HTTP $HTTP_CODE"

# --- Test 2: Zero-byte file upload ---
echo "-> Uploading zero-byte file..."
ZERO_FILE=$(mktemp)
DOWNLOAD_FILE=$(mktemp)
trap 'rm -f "$ZERO_FILE" "$DOWNLOAD_FILE"' EXIT
> "$ZERO_FILE"  # Create empty file

UPLOAD_URL=$(presign_rq "upload")
BLOB_ID=$(curl -fsS "$UPLOAD_URL" --data-binary @"$ZERO_FILE" | jq -r '.blob_id')
echo "  Blob ID: $BLOB_ID"

echo "-> Downloading zero-byte file..."
DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")
download_file "$DOWNLOAD_URL" "$DOWNLOAD_FILE"

DOWNLOAD_SIZE=$(wc -c < "$DOWNLOAD_FILE")
if [[ "$DOWNLOAD_SIZE" -ne 0 ]]; then
    test_failed "Negative Cases" "Zero-byte file download should be 0 bytes, got $DOWNLOAD_SIZE"
fi
echo "  Zero-byte file round-trip successful (0 bytes)"

# --- Test 3: Default Content-Type when none specified ---
echo "-> Uploading file without Content-Type header..."
UPLOAD_URL=$(presign_rq "upload")
# Use -H to explicitly unset Content-Type (curl might set one)
BLOB_ID2=$(curl -fsS "$UPLOAD_URL" \
    -H "Content-Type:" \
    --data-binary @"data/number-1" | jq -r '.blob_id')
echo "  Blob ID: $BLOB_ID2"

DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID2")
RESPONSE=$(curl -i -fsS "$DOWNLOAD_URL" 2>&1)
RECEIVED_TYPE=$(echo "$RESPONSE" | grep -i "^content-type:" | cut -d: -f2- | tr -d '\r' | xargs)

echo "  Received Content-Type: $RECEIVED_TYPE"
if [[ "$RECEIVED_TYPE" != "application/octet-stream" ]]; then
    test_failed "Negative Cases" "Expected default Content-Type 'application/octet-stream', got '$RECEIVED_TYPE'"
fi
echo "  Default Content-Type correctly applied"

# --- Test 4: Unknown endpoint returns non-200 (404 or 401) ---
echo "-> Requesting unknown endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/nonexistent/endpoint")

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Negative Cases" "Unknown endpoint should not return 200"
fi
echo "  Unknown endpoint returned HTTP $HTTP_CODE (non-200, as expected)"

test_success "Negative Cases and Edge Cases"
