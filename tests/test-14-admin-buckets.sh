#!/usr/bin/env bash
#
# Test: Admin bucket management - list, delete empty, reject delete non-empty
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Admin Bucket Management"

BUCKET="admin-test-$(date +%s)"

echo "-> Uploading file to bucket '$BUCKET'..."
UPLOAD_URL=$(presign_rq "upload" "" "$BUCKET")
BLOB_ID=$(upload_file "data/number-1" "$UPLOAD_URL")
echo "  Blob ID: $BLOB_ID"

# --- Test 1: List buckets ---
echo "-> Listing all buckets..."
BUCKETS_RES=$(curl -fsS "$HOST/admin/buckets" \
    -H "Authorization: Bearer $API_KEY")

BUCKET_NAMES=$(echo "$BUCKETS_RES" | jq -r '.buckets[].name')
if ! echo "$BUCKET_NAMES" | grep -q "$BUCKET"; then
    test_failed "Admin Buckets" "Bucket '$BUCKET' not found in bucket list"
fi
echo "  Bucket '$BUCKET' found in list"

# --- Test 2: Delete non-empty bucket (should fail) ---
echo "-> Attempting to delete non-empty bucket (should fail)..."
DEL_RES=$(curl -sS -X DELETE "$HOST/admin/buckets/$BUCKET" \
    -H "Authorization: Bearer $API_KEY")
DEL_SUCCESS=$(echo "$DEL_RES" | jq -r '.success')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$HOST/admin/buckets/$BUCKET" \
    -H "Authorization: Bearer $API_KEY")

if [[ "$DEL_SUCCESS" == "true" ]]; then
    test_failed "Admin Buckets" "Delete of non-empty bucket should have failed"
fi
echo "  Non-empty bucket delete rejected (success=$DEL_SUCCESS, HTTP $HTTP_CODE)"

# --- Test 3: Delete blob, then delete empty bucket ---
echo "-> Deleting blob from bucket..."
DELETE_URL=$(presign_rq "delete" "$BLOB_ID" "$BUCKET")
delete_file "$DELETE_URL"
echo "  Blob deleted"

echo "-> Deleting now-empty bucket..."
DEL_RES=$(curl -fsS -X DELETE "$HOST/admin/buckets/$BUCKET" \
    -H "Authorization: Bearer $API_KEY")
DEL_SUCCESS=$(echo "$DEL_RES" | jq -r '.success')

if [[ "$DEL_SUCCESS" != "true" ]]; then
    test_failed "Admin Buckets" "Delete of empty bucket should have succeeded, got: $(echo "$DEL_RES" | jq -c '.')"
fi
echo "  Empty bucket deleted successfully"

# --- Test 4: Verify bucket no longer in list ---
echo "-> Verifying bucket removed from list..."
BUCKETS_AFTER=$(curl -fsS "$HOST/admin/buckets" \
    -H "Authorization: Bearer $API_KEY")

if echo "$BUCKETS_AFTER" | jq -r '.buckets[].name' | grep -q "^${BUCKET}$"; then
    test_failed "Admin Buckets" "Bucket '$BUCKET' should not appear in list after deletion"
fi
echo "  Bucket no longer in list"

test_success "Admin Bucket Management"
