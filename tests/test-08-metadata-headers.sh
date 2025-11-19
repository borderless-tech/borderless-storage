#!/usr/bin/env bash
#
# Test: Upload file with Content-Type and Content-Disposition headers, verify they're preserved
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Metadata Headers (Content-Type, Content-Disposition)"

CONTENT_TYPE="text/markdown; charset=utf-8"
CONTENT_DISPOSITION='attachment; filename="my-doc.md"'

echo "→ Uploading file with metadata headers..."
UPLOAD_URL=$(presign_rq "upload")
BLOB_ID=$(curl -fsS "$UPLOAD_URL" \
    -H "Content-Type: $CONTENT_TYPE" \
    -H "Content-Disposition: $CONTENT_DISPOSITION" \
    --data-binary @"data/manifesto.md" | jq -r '.blob_id')

echo "  Blob ID: $BLOB_ID"

echo "→ Downloading and checking response headers..."
DOWNLOAD_URL=$(presign_rq "download" "$BLOB_ID")
RESPONSE=$(curl -i -fsS "$DOWNLOAD_URL" 2>&1)

# Extract headers
RECEIVED_TYPE=$(echo "$RESPONSE" | grep -i "^content-type:" | cut -d: -f2- | tr -d '\r' | xargs)
RECEIVED_DISP=$(echo "$RESPONSE" | grep -i "^content-disposition:" | cut -d: -f2- | tr -d '\r' | xargs)

echo "  Sent Content-Type: $CONTENT_TYPE"
echo "  Received Content-Type: $RECEIVED_TYPE"

if [[ "$RECEIVED_TYPE" != "$CONTENT_TYPE" ]]; then
    test_failed "Metadata Headers" "Content-Type mismatch: expected '$CONTENT_TYPE', got '$RECEIVED_TYPE'"
fi

echo "  ✓ Content-Type preserved"

echo "  Sent Content-Disposition: $CONTENT_DISPOSITION"
echo "  Received Content-Disposition: $RECEIVED_DISP"

# Content-Disposition can have quotes or not - both are valid
# Just check that it contains the key parts: "attachment" and "my-doc.md"
if [[ ! "$RECEIVED_DISP" =~ attachment.*my-doc\.md ]]; then
    test_failed "Metadata Headers" "Content-Disposition doesn't contain expected parts: got '$RECEIVED_DISP'"
fi

echo "  ✓ Content-Disposition preserved"

test_success "Metadata Headers"
