#!/usr/bin/env bash
#
# Utility functions for writing e2e-tests with shell scripts.
#
# You can also use the progress_bar function to create a nice progress bar in your for-loops.
#
# Also make sure that the base environment values match

export API_KEY="secret-api-key"
export HOST="http://127.0.0.1:3000"

assertSetup() {
    # Check, if the required tools for testing are installed
    checkTool curl
    checkTool jq
    checkTool mktemp
    checkTool sha256sum
    checkTool uuidgen

    # Check, that the server is reachable
    if ! curl -fsS "http://localhost:3000/healthz" > /dev/null 2>&1; then
        echo "Server is not reachable via localhost:3000"
        echo "Please ensure that the server is up and running to execute the tests"
        exit 3
    fi
}

checkTool() {
    TOOL="$1"
    if ! command -v $TOOL > /dev/null 2>&1; then
        echo "Missing $TOOL - make sure that $TOOL is installed before continuing with the tests."
        exit 2
    fi
}


# Create a function for a progress bar indicator '#' function to update and display the progress bar
#
# Parameters: progress [number] - counter for your progress
#             total    [number] - max. value for the counter
show_progress() {
    local progress=$1
    local total=$2
    local width=50
    local progress_percent=$(( progress * 100 / total ))
    local filled_length=$(( progress_percent * width / 100 ))
    local bar=""
    local i # otherwise we might interfere with outer definitions of "i"
    for (( i=0; i<filled_length; i++ )); do
        bar="${bar}#"
    done
    for (( i=filled_length; i<width; i++ )); do
        bar="${bar}-"
    done
    printf "\r[%-50s] %d%% (%d/%d)" "$bar" "$progress_percent" "$progress" "$total"
}


# Creates a post request with some json data as body
#
# Parameters: endpoint [string] - endpoint
#             data     [string] - json-data
#
# Example:
# post_json 127.0.0.1:6000/endpoint '{"data": 42}'
#
# Please don't forget to properly escape your json string
post_json() {
    local endpoint="$1"
    local json_data="$2"
    curl -s -X POST -H "Content-Type: application/json" -d "$json_data" "$endpoint"
}

# Returns the presigned url for some blob-id and action
presign_rq() {
    local ACTION="$1"
    local BLOB="$2"
    local BUCKET="$3"

    local RES=""
    local PAYLOAD=""

    if [[ $BUCKET ]]; then
        if [[ $BLOB ]]; then
            PAYLOAD='{ "action": "'''$ACTION'''", "blob_id": "'''$BLOB'''", "bucket": "'''$BUCKET'''" }'
        else
            PAYLOAD='{ "action": "'''$ACTION'''", "bucket": "'''$BUCKET'''" }'
        fi
    elif [[ $BLOB ]]; then
        PAYLOAD='{ "action": "'''$ACTION'''", "blob_id": "'''$BLOB'''" }'
    else
        PAYLOAD='{ "action": "'''$ACTION'''" }'
    fi

    RES=$(curl -fsS $HOST/presign \
        -H "authorization: Bearer $API_KEY" \
        -H "content-type: application/json" \
        -d "$PAYLOAD")

    if [[ $(echo "$RES" | jq '.success') != "true" ]]; then
        echo "Failed to obtain presign response" >&2
        echo "$RES" >&2
        exit 5
   fi
   echo "$RES" | jq -r '.url'
}

# Upload a file to a presigned URL
# Returns: blob_id
upload_file() {
    local FILE="$1"
    local URL="$2"

    local RES=$(curl -fsS "$URL" --data-binary @"$FILE")
    if [[ $(echo "$RES" | jq '.success') != "true" ]]; then
        echo "Upload failed" >&2
        echo "$RES" >&2
        return 1
    fi
    echo "$RES" | jq -r '.blob_id'
}

# Updates a file to a presigned URL
# Similar to "Upload", but is able to overwrite files
# Returns: blob_id
update_file() {
    local FILE="$1"
    local URL="$2"

    local RES=$(curl -X PUT -fsS "$URL" --data-binary @"$FILE")
    if [[ $(echo "$RES" | jq '.success') != "true" ]]; then
        echo "Upload failed" >&2
        echo "$RES" >&2
        return 1
    fi
    echo "$RES" | jq -r '.blob_id'
}

# Download a file from a presigned URL
download_file() {
    local URL="$1"
    local OUTPUT="$2"

    curl -fsS "$URL" -o "$OUTPUT"
}

# Delete a file using presigned URL
delete_file() {
    local URL="$1"

    local RES=$(curl -fsS -X DELETE "$URL")
    if [[ $(echo "$RES" | jq '.success') != "true" ]]; then
        echo "Delete failed" >&2
        echo "$RES" >&2
        return 1
    fi
    return 0
}

# Check if two files have the same SHA256 hash
assert_hash_match() {
    local FILE1="$1"
    local FILE2="$2"
    local DESC="${3:-files}"

    local HASH1=$(sha256sum "$FILE1" | awk '{print $1}')
    local HASH2=$(sha256sum "$FILE2" | awk '{print $1}')

    if [[ "$HASH1" != "$HASH2" ]]; then
        echo "❌ Hash mismatch for $DESC"
        echo "   File 1: $HASH1"
        echo "   File 2: $HASH2"
        exit 1
    fi
    echo "✓ Hash match for $DESC"
}

# Assert that a command fails with non-zero exit code
assert_fails() {
    local DESC="$1"
    shift

    if "$@" > /dev/null 2>&1; then
        echo "❌ Expected failure but succeeded: $DESC"
        exit 1
    fi
    echo "✓ Failed as expected: $DESC"
}

# Get admin stats
get_stats() {
    curl -fsS "$HOST/admin/stats" \
        -H "Authorization: Bearer $API_KEY" | jq '.'
}

# Get admin objects list
get_objects() {
    local BUCKET="${1:-}"
    local ENDPOINT="$HOST/admin/objects"
    if [[ $BUCKET ]]; then
        ENDPOINT="$HOST/admin/objects/$BUCKET"
    fi

    curl -fsS "$ENDPOINT" \
        -H "Authorization: Bearer $API_KEY" | jq '.'
}

# Get bucket info
get_bucket() {
    local BUCKET="$1"
    curl -fsS "$HOST/admin/buckets/$BUCKET" \
        -H "Authorization: Bearer $API_KEY" | jq '.'
}

# Test output helpers
test_start() {
    echo ""
    echo "=========================================="
    echo "TEST: $1"
    echo "=========================================="
}

test_success() {
    echo ""
    echo "✅ TEST PASSED: $1"
    echo ""
}

test_failed() {
    echo ""
    echo "❌ TEST FAILED: $1"
    echo "   $2"
    echo ""
    exit 1
}
