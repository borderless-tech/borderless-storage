#!/usr/bin/env bash
#
# Test: Upload a file twice - POST should fail, PUT should succeed and update content
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Double Upload - POST fails, PUT succeeds"

# Generate test files with different content
TEMP_FILE1=$(mktemp)
TEMP_FILE2=$(mktemp)
DOWNLOAD=$(mktemp)
trap 'rm -f "$TEMP_FILE1" "$TEMP_FILE2" "$DOWNLOAD"' EXIT

echo "content1" > "$TEMP_FILE1"
echo "content2-different" > "$TEMP_FILE2"

echo "→ First upload (POST)..."
UPLOAD_URL=$(presign_rq "upload")
BLOB_ID=$(upload_file "$TEMP_FILE1" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

echo "→ Second upload to same blob (POST) - should fail..."
UPLOAD_URL2=$(presign_rq "upload" "$BLOB_ID")
if curl -fsS "$UPLOAD_URL2" --data-binary @"$TEMP_FILE2" > /dev/null 2>&1; then
    test_failed "Double Upload" "POST to existing blob should have failed but succeeded"
fi
echo "  ✓ POST failed as expected"

echo "→ Update using PUT..."
UPLOAD_URL3=$(presign_rq "update" "$BLOB_ID")
update_file "$TEMP_FILE2" "$UPLOAD_URL3" > /dev/null

echo "→ Download and verify content was updated..."
DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")
download_file "$DOWNLOAD_URL" "$DOWNLOAD"

assert_hash_match "$TEMP_FILE2" "$DOWNLOAD" "updated file"

test_success "Double Upload"
