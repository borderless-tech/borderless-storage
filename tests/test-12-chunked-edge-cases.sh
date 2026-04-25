#!/usr/bin/env bash
#
# Test: Chunked upload edge cases - missing chunks on merge, invalid chunk index
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Chunked Upload Edge Cases"

# --- Test 1: Merge with missing chunks ---
echo "-> Setting up chunked upload (3 chunks, only sending 1 and 3)..."
BLOB_ID=$(uuidgen)
UPLOAD_URL=$(presign_rq "upload" "$BLOB_ID")

# Send chunk 1 of 3
echo "chunk1-data" | curl -X POST -fsS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-index: 1" \
    -H "x-chunk-total: 3" \
    --data-binary @- > /dev/null

# Skip chunk 2, send chunk 3
echo "chunk3-data" | curl -X POST -fsS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-index: 3" \
    -H "x-chunk-total: 3" \
    --data-binary @- > /dev/null

echo "-> Requesting merge (should report missing chunk 2)..."
MERGE_RES=$(curl -X POST -sS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-merge: 1" \
    -H "x-chunk-total: 3")

MERGE_SUCCESS=$(echo "$MERGE_RES" | jq -r '.success')
MISSING=$(echo "$MERGE_RES" | jq -r '.missing_chunks')

if [[ "$MERGE_SUCCESS" != "false" ]]; then
    test_failed "Chunked Edge Cases" "Merge with missing chunks should return success=false, got: $MERGE_SUCCESS"
fi

echo "  Merge correctly returned success=false"
echo "  Missing chunks: $MISSING"

# Verify chunk 2 is in the missing list
if ! echo "$MISSING" | jq -e 'index(2)' > /dev/null 2>&1; then
    test_failed "Chunked Edge Cases" "Expected chunk 2 in missing_chunks, got: $MISSING"
fi
echo "  Chunk 2 correctly reported as missing"

# --- Test 2: Invalid chunk index (index > total) ---
echo "-> Sending chunk with index > total (should fail)..."
BLOB_ID2=$(uuidgen)
UPLOAD_URL2=$(presign_rq "upload" "$BLOB_ID2")

HTTP_CODE=$(echo "bad-chunk" | curl -X POST -s -o /dev/null -w "%{http_code}" "$UPLOAD_URL2" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-index: 5" \
    -H "x-chunk-total: 3" \
    --data-binary @-)

if [[ "$HTTP_CODE" == "200" ]]; then
    test_failed "Chunked Edge Cases" "Chunk index > total should have been rejected but got HTTP 200"
fi
echo "  Invalid chunk index rejected with HTTP $HTTP_CODE"

test_success "Chunked Upload Edge Cases"
