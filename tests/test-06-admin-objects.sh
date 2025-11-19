#!/usr/bin/env bash
#
# Test: Upload a file and verify it appears in admin/objects endpoint
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Admin Objects Endpoint"

echo "→ Getting initial object count..."
INITIAL_OBJECTS=$(get_objects | jq -r '.total')
echo "  Initial objects: $INITIAL_OBJECTS"

echo "→ Uploading file..."
UPLOAD_URL=$(presign_rq "upload")
BLOB_ID=$(upload_file "data/number-1" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

echo "→ Getting updated object count..."
UPDATED_OBJECTS=$(get_objects | jq -r '.total')
echo "  Updated objects: $UPDATED_OBJECTS"

if [[ "$UPDATED_OBJECTS" -le "$INITIAL_OBJECTS" ]]; then
    test_failed "Admin Objects" "Expected object count to increase from $INITIAL_OBJECTS to $UPDATED_OBJECTS"
fi

echo "→ Verifying uploaded blob is in objects list..."
OBJECTS=$(get_objects)
FOUND=$(echo "$OBJECTS" | jq -r --arg id "$BLOB_ID" '.objects[] | select(.blob_id == $id) | .blob_id')

if [[ "$FOUND" != "$BLOB_ID" ]]; then
    test_failed "Admin Objects" "Uploaded blob $BLOB_ID not found in objects list"
fi

echo "  ✓ Blob found in objects list"

test_success "Admin Objects"
