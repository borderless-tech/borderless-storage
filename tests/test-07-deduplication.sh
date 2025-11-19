#!/usr/bin/env bash
#
# Test: Upload the same file twice and verify deduplication in stats
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Deduplication"

echo "→ Getting initial stats..."
INITIAL_STATS=$(get_stats)
INITIAL_UNIQUE=$(echo "$INITIAL_STATS" | jq -r '.stats.unique_content_count')
echo "  Initial unique content files: $INITIAL_UNIQUE"

echo "→ Uploading file first time..."
UPLOAD_URL1=$(presign_rq "upload")
BLOB_ID1=$(upload_file "data/manifesto.md" "$UPLOAD_URL1")
echo "  Blob ID 1: $BLOB_ID1"

echo "→ Uploading same file second time..."
UPLOAD_URL2=$(presign_rq "upload")
BLOB_ID2=$(upload_file "data/manifesto.md" "$UPLOAD_URL2")
echo "  Blob ID 2: $BLOB_ID2"

if [[ "$BLOB_ID1" == "$BLOB_ID2" ]]; then
    test_failed "Deduplication" "Got same blob ID for two uploads: $BLOB_ID1"
fi

echo "→ Getting updated stats..."
sleep 1  # Give time for stats to update
UPDATED_STATS=$(get_stats)
UPDATED_UNIQUE=$(echo "$UPDATED_STATS" | jq -r '.stats.unique_content_count')
TOTAL_OBJECTS=$(echo "$UPDATED_STATS" | jq -r '.stats.total_objects')
DEDUP_PERCENTAGE=$(echo "$UPDATED_STATS" | jq -r '.stats.deduplication_percentage')

echo "  Unique content files: $UPDATED_UNIQUE"
echo "  Total objects: $TOTAL_OBJECTS"
echo "  Deduplication: $DEDUP_PERCENTAGE"

# Check if deduplication worked
# Since we uploaded the same file twice, unique content should NOT increase
# But total objects should have increased by 2
OBJECTS_INCREASE=$((TOTAL_OBJECTS - INITIAL_UNIQUE))

if [[ "$UPDATED_UNIQUE" -eq "$INITIAL_UNIQUE" ]]; then
    echo "  ✓ Deduplication working: unique content stayed at $UPDATED_UNIQUE"
    echo "  ✓ Same content file reused for both uploads"
elif [[ "$UPDATED_UNIQUE" -eq $((INITIAL_UNIQUE + 1)) ]]; then
    echo "  ✓ Content count increased by 1 (first upload of this file)"
    echo "  ✓ Both uploads share the same content hash"
else
    test_failed "Deduplication" "Expected unique content to be $INITIAL_UNIQUE or $((INITIAL_UNIQUE + 1)), got $UPDATED_UNIQUE"
fi

test_success "Deduplication"
