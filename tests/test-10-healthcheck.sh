#!/usr/bin/env bash
#
# Test: Verify health check and stats endpoints work correctly
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Health Check and Stats"

echo "→ Testing /healthz endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/healthz")

if [[ "$HTTP_CODE" != "200" ]]; then
    test_failed "Health Check" "Expected HTTP 200, got $HTTP_CODE"
fi
echo "  ✓ Health check returns 200"

echo "→ Testing /admin/stats endpoint..."
STATS=$(get_stats)
SUCCESS=$(echo "$STATS" | jq -r '.success')

if [[ "$SUCCESS" != "true" ]]; then
    test_failed "Stats Endpoint" "Stats endpoint returned success=false"
fi
echo "  ✓ Stats endpoint accessible"

echo "→ Verifying stats structure..."
TOTAL_OBJECTS=$(echo "$STATS" | jq -r '.stats.total_objects')
UNIQUE_CONTENT=$(echo "$STATS" | jq -r '.stats.unique_content_count')
ACTUAL_SIZE=$(echo "$STATS" | jq -r '.stats.actual_storage_size')
LOGICAL_SIZE=$(echo "$STATS" | jq -r '.stats.total_logical_size')
DEDUP_PCT=$(echo "$STATS" | jq -r '.stats.deduplication_percentage')

echo "  Total objects: $TOTAL_OBJECTS"
echo "  Unique content: $UNIQUE_CONTENT"
echo "  Actual storage: $ACTUAL_SIZE bytes"
echo "  Logical storage: $LOGICAL_SIZE bytes"
echo "  Deduplication: $DEDUP_PCT"

# Verify all values are numbers
if ! [[ "$TOTAL_OBJECTS" =~ ^[0-9]+$ ]]; then
    test_failed "Stats Endpoint" "total_objects is not a number: $TOTAL_OBJECTS"
fi

if ! [[ "$UNIQUE_CONTENT" =~ ^[0-9]+$ ]]; then
    test_failed "Stats Endpoint" "unique_content_count is not a number: $UNIQUE_CONTENT"
fi

echo "  ✓ Stats structure valid"

test_success "Health Check and Stats"
