#!/usr/bin/env bash
#
# Master test runner - runs all e2e tests sequentially
#

set -e
cd "$(dirname "$0")"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
TOTAL=0

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Borderless Storage E2E Test Suite                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if server is running
if ! curl -fsS "http://localhost:3000/healthz" > /dev/null 2>&1; then
    echo -e "${RED}❌ Server is not running on localhost:3000${NC}"
    echo "   Please start the server before running tests"
    echo ""
    echo "   You can use: ./start-server.sh"
    exit 1
fi

echo -e "${GREEN}✓ Server is running${NC}"
echo ""

# Find all test scripts (test-*.sh)
TESTS=($(ls test-*.sh 2>/dev/null | sort))

if [ ${#TESTS[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠ No test files found${NC}"
    exit 0
fi

echo "Found ${#TESTS[@]} tests to run"
echo ""

START_TIME=$(date +%s)

# Run each test
for TEST in "${TESTS[@]}"; do
    TOTAL=$((TOTAL + 1))
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Running: $TEST"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if bash "$TEST"; then
        PASSED=$((PASSED + 1))
        echo -e "${GREEN}✅ PASSED${NC}: $TEST"
    else
        FAILED=$((FAILED + 1))
        echo -e "${RED}❌ FAILED${NC}: $TEST"
        echo ""
        echo "Stopping test suite due to failure."
        break
    fi
    echo ""
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Test Summary                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "  Total:   $TOTAL tests"
echo -e "  ${GREEN}Passed:  $PASSED${NC}"
echo -e "  ${RED}Failed:  $FAILED${NC}"
echo "  Duration: ${DURATION}s"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              🎉 ALL TESTS PASSED! 🎉                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                ❌ TESTS FAILED ❌                          ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    exit 1
fi
