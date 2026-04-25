#!/usr/bin/env bash
#
# Test: Deduplication refcount - deleting one blob doesn't remove shared content
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Deduplication Refcount"

DOWNLOAD=$(mktemp)
trap 'rm -f "$DOWNLOAD"' EXIT

echo "-> Uploading same file to two different blobs..."
UPLOAD_URL1=$(presign_rq "upload")
BLOB_ID1=$(upload_file "data/manifesto.md" "$UPLOAD_URL1")
echo "  Blob 1: $BLOB_ID1"

UPLOAD_URL2=$(presign_rq "upload")
BLOB_ID2=$(upload_file "data/manifesto.md" "$UPLOAD_URL2")
echo "  Blob 2: $BLOB_ID2"

if [[ "$BLOB_ID1" == "$BLOB_ID2" ]]; then
    test_failed "Dedup Refcount" "Got same blob ID for two uploads"
fi

echo "-> Getting stats before delete..."
STATS_BEFORE=$(get_stats)
UNIQUE_BEFORE=$(echo "$STATS_BEFORE" | jq -r '.stats.unique_content_count')
echo "  Unique content before: $UNIQUE_BEFORE"

echo "-> Deleting blob 1..."
DELETE_URL=$(presign_rq "delete" "$BLOB_ID1")
delete_file "$DELETE_URL"
echo "  Blob 1 deleted"

echo "-> Verifying blob 1 download now fails..."
DOWNLOAD_URL1=$(presign_rq "download" "$BLOB_ID1")
assert_fails "download deleted blob 1" download_file "$DOWNLOAD_URL1" "$DOWNLOAD"

echo "-> Verifying blob 2 still works..."
DOWNLOAD_URL2=$(presign_rq "download" "$BLOB_ID2")
download_file "$DOWNLOAD_URL2" "$DOWNLOAD"
assert_hash_match "data/manifesto.md" "$DOWNLOAD" "blob 2 after blob 1 deleted"

echo "-> Getting stats after delete..."
STATS_AFTER=$(get_stats)
UNIQUE_AFTER=$(echo "$STATS_AFTER" | jq -r '.stats.unique_content_count')
echo "  Unique content after: $UNIQUE_AFTER"

if [[ "$UNIQUE_AFTER" -ne "$UNIQUE_BEFORE" ]]; then
    test_failed "Dedup Refcount" "Unique content count changed from $UNIQUE_BEFORE to $UNIQUE_AFTER (content should still be referenced)"
fi
echo "  Unique content count unchanged (refcount working)"

test_success "Deduplication Refcount"
