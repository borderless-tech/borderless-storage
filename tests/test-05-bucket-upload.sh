#!/usr/bin/env bash
#
# Test: Upload to a specific bucket and verify bucket size increases
# Also tests that buckets with invalid names are rejected.

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Bucket-specific Upload"

BUCKET="test-bucket-$(date +%s)"

echo "→ Getting initial bucket info (should not exist)..."
if get_bucket "$BUCKET" > /dev/null 2>&1; then
    echo "  Bucket already exists (will be reused)"
fi

echo "→ Uploading file to bucket '$BUCKET'..."
UPLOAD_URL=$(presign_rq "upload" "" "$BUCKET")
BLOB_ID=$(upload_file "data/manifesto.md" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

echo "→ Getting bucket info after upload..."
BUCKET_INFO=$(get_bucket "$BUCKET")
OBJECT_COUNT=$(echo "$BUCKET_INFO" | jq -r '.bucket.object_count')
TOTAL_SIZE=$(echo "$BUCKET_INFO" | jq -r '.bucket.total_size')

echo "  Object count: $OBJECT_COUNT"
echo "  Total size: $TOTAL_SIZE bytes"

if [[ "$OBJECT_COUNT" -lt 1 ]]; then
    test_failed "Bucket Upload" "Expected at least 1 object in bucket, got $OBJECT_COUNT"
fi

if [[ "$TOTAL_SIZE" -lt 1 ]]; then
    test_failed "Bucket Upload" "Expected total_size > 0, got $TOTAL_SIZE"
fi

echo "→ Downloading from bucket to verify..."
DOWNLOAD=$(mktemp)
trap 'rm -f "$DOWNLOAD"' EXIT

DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID" "$BUCKET")
download_file "$DOWNLOAD_URL" "$DOWNLOAD"

assert_hash_match "data/manifesto.md" "$DOWNLOAD" "bucket upload"

echo "→ Testing invalid bucket names (should fail)..."

# Helper function to test invalid bucket name
test_invalid_bucket() {
    local bucket_name="$1"
    local description="$2"

    echo "  Testing $description..."
    local PAYLOAD='{ "action": "upload", "bucket": "'"$bucket_name"'" }'
    local RES=$(curl -fsS $HOST/presign \
        -H "authorization: Bearer $API_KEY" \
        -H "content-type: application/json" \
        -d "$PAYLOAD" 2>&1) || true

    # Check if request succeeded (it shouldn't)
    if echo "$RES" | jq -e '.success == true' > /dev/null 2>&1; then
        test_failed "Bucket Upload" "$description should have been rejected"
    fi

    echo "  ✓ $description rejected"
}

# Test various invalid bucket names
test_invalid_bucket "invalid bucket" "bucket name with spaces"
test_invalid_bucket "invalid.bucket" "bucket name with dots"
test_invalid_bucket "invalid/bucket" "bucket name with slashes"
test_invalid_bucket "invalid@bucket" "bucket name with @"

echo "→ Testing uppercase bucket name normalization..."
UPPER_BUCKET="TestBucket-$(date +%s)"
UPLOAD_URL=$(presign_rq "upload" "" "$UPPER_BUCKET")
BLOB_ID2=$(upload_file "data/number-1" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID2"

# Verify bucket was created with lowercase name
LOWER_BUCKET=$(echo "$UPPER_BUCKET" | tr '[:upper:]' '[:lower:]')
BUCKET_INFO=$(get_bucket "$LOWER_BUCKET")
if [[ $(echo "$BUCKET_INFO" | jq -r '.bucket.name') != "$LOWER_BUCKET" ]]; then
    test_failed "Bucket Upload" "Expected bucket name to be normalized to lowercase: $LOWER_BUCKET"
fi
echo "  ✓ Uppercase bucket name normalized to lowercase: $LOWER_BUCKET"

test_success "Bucket Upload"
