#!/usr/bin/env bash
#
# Test: Orphan cleanup - stale chunks are removed by background cleanup
#
# NOTE: Requires server started with TTL_ORPHAN_SECS=5 (as in start-server.sh)
# This test takes ~15 seconds due to waiting for the cleanup cycle.
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Orphan Cleanup (stale chunks)"

echo "-> Starting chunked upload (will abandon without merging)..."
BLOB_ID=$(uuidgen)
UPLOAD_URL=$(presign_rq "upload" "$BLOB_ID")

# Send 2 of 3 chunks
echo "chunk1" | curl -X POST -fsS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-index: 1" \
    -H "x-chunk-total: 3" \
    --data-binary @- > /dev/null

echo "chunk2" | curl -X POST -fsS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-index: 2" \
    -H "x-chunk-total: 3" \
    --data-binary @- > /dev/null

echo "  Uploaded 2 of 3 chunks for blob $BLOB_ID"

echo "-> Waiting for orphan cleanup cycle (~15s)..."
echo "  (TTL_ORPHAN_SECS=5, cleanup interval=10s)"
sleep 16

echo "-> Attempting merge after cleanup (should report missing chunks or fail)..."
# The chunks should have been cleaned up by now
MERGE_RES=$(curl -X POST -sS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-merge: 1" \
    -H "x-chunk-total: 3")

MERGE_SUCCESS=$(echo "$MERGE_RES" | jq -r '.success')

if [[ "$MERGE_SUCCESS" == "true" ]]; then
    test_failed "Orphan Cleanup" "Merge should have failed after cleanup, but succeeded"
fi
echo "  Merge correctly failed after cleanup: $(echo "$MERGE_RES" | jq -r '.message')"

test_success "Orphan Cleanup (stale chunks)"
