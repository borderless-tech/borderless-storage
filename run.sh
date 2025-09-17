#!/usr/bin/env bash

# Go in directory of the script
cd $(dirname $0)

# Use environment variables to configure the service
export IP_ADDR="127.0.0.1:3000"
export DATA_DIR="db"
export DOMAIN="http://localhost:3000"

cargo run
