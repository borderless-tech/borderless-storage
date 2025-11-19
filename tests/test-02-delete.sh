#!/usr/bin/env bash
#
# Test: Upload a file, delete it, then verify download fails
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Upload, Delete, Download should fail"

echo "→ Uploading file..."
UPLOAD_URL=$(presign_rq "upload")
BLOB_ID=$(upload_file "data/number-1" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

echo "→ Deleting file..."
DELETE_URL=$(presign_rq "delete" "$BLOB_ID")
delete_file "$DELETE_URL"
echo "  ✓ Delete successful"

echo "→ Verifying download now fails..."
DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")
DOWNLOAD=$(mktemp)
trap 'rm -f "$DOWNLOAD"' EXIT

assert_fails "download after delete" download_file "$DOWNLOAD_URL" "$DOWNLOAD"

test_success "Delete"
