#!/usr/bin/env bash
#
# Test: Upload a file in chunks, then download and verify SHA256 hash matches
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Chunked Upload and Download"

# Use manifesto.md for chunked upload
ORIGINAL="data/manifesto.md"
FILE_SIZE=$(wc -c < "$ORIGINAL")
CHUNK_SIZE=50  # Small chunks for testing
TOTAL_CHUNKS=$(( (FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE ))

echo "→ File size: $FILE_SIZE bytes"
echo "→ Chunk size: $CHUNK_SIZE bytes"
echo "→ Total chunks: $TOTAL_CHUNKS"

# Get single presigned upload URL (used for all chunks and merge)
echo "→ Requesting presigned upload URL..."
BLOB_ID=$(uuidgen)
UPLOAD_URL=$(presign_rq "upload" "$BLOB_ID")

# Upload each chunk with x-upload-type, x-chunk-index, x-chunk-total headers
for (( i=0; i<TOTAL_CHUNKS; i++ )); do
    # Split file into chunks (index is 1-based according to README)
    OFFSET=$(( i * CHUNK_SIZE ))
    CHUNK_FILE=$(mktemp)
    dd if="$ORIGINAL" of="$CHUNK_FILE" bs=1 skip=$OFFSET count=$CHUNK_SIZE 2>/dev/null

    echo "  → Uploading chunk $((i+1))/$TOTAL_CHUNKS..."
    curl -X POST -fsS "$UPLOAD_URL" \
        -H "x-upload-type: chunked" \
        -H "x-chunk-index: $((i+1))" \
        -H "x-chunk-total: $TOTAL_CHUNKS" \
        --data-binary @"$CHUNK_FILE" > /dev/null

    rm "$CHUNK_FILE"
done

# Send merge request
echo "→ Requesting chunk merge..."
curl -X POST -fsS "$UPLOAD_URL" \
    -H "x-upload-type: chunked" \
    -H "x-chunk-merge: true" \
    -H "x-chunk-total: $TOTAL_CHUNKS" > /dev/null

echo "→ Waiting for merge to complete..."
sleep 1

echo "→ Downloading merged file..."
DOWNLOAD=$(mktemp)
trap 'rm -f "$DOWNLOAD"' EXIT

DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")
download_file "$DOWNLOAD_URL" "$DOWNLOAD"

echo "→ Verifying SHA256 hash..."
assert_hash_match "$ORIGINAL" "$DOWNLOAD" "chunked upload"

test_success "Chunked Upload"
