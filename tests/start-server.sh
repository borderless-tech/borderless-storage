#!/usr/bin/env bash

# Go into the base directory
BASE=$(dirname "$0")
cd "$BASE/.." || exit 1

# Create temporary directory for data-storage
DB=$(mktemp -d)

echo "Using temporary directory for data storage: $DB"

# Use environment variables to configure the service
export IP_ADDR="127.0.0.1:3000"
export DATA_DIR="$DB"
export DOMAIN="http://localhost:3000"
export PRESIGN_API_KEY="secret-api-key"
export RQ_TIMEOUT_SECS=1
export TTL_ORPHAN_SECS=5 # for testing

# Run service with high verbosity
cargo run -- --verbose
