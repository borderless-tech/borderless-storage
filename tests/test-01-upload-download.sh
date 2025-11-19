#!/usr/bin/env bash
#
# Test: Upload a file and download it back, verify SHA256 hash matches
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Upload and Download - SHA256 verification"

# Create temp file for download
DOWNLOAD=$(mktemp)
trap 'rm -f "$DOWNLOAD"' EXIT

echo "→ Requesting presigned upload URL..."
UPLOAD_URL=$(presign_rq "upload")

echo "→ Uploading file..."
BLOB_ID=$(upload_file "data/manifesto.md" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

echo "→ Requesting presigned download URL..."
DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")

echo "→ Downloading file..."
download_file "$DOWNLOAD_URL" "$DOWNLOAD"

echo "→ Verifying SHA256 hash..."
assert_hash_match "data/manifesto.md" "$DOWNLOAD" "uploaded and downloaded file"

test_success "Upload and Download"
