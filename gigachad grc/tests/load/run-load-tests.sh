#!/bin/bash

# Load Test Runner Script for GigaChad GRC
# Usage: ./run-load-tests.sh [smoke|load|stress|spike|soak|all]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
BASE_URL="${K6_BASE_URL:-http://localhost:3001}"
TEST_TYPE="${1:-smoke}"
RESULTS_DIR="$(dirname "$0")/results"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Print header
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              GigaChad GRC Load Test Runner                           ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║  Target URL: ${BASE_URL}${NC}"
echo -e "${BLUE}║  Test Type:  ${TEST_TYPE}${NC}"
echo -e "${BLUE}║  Results:    ${RESULTS_DIR}${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if k6 is installed
if ! command -v k6 &> /dev/null; then
    echo -e "${RED}Error: k6 is not installed.${NC}"
    echo "Install with: brew install k6 (macOS) or see https://k6.io/docs/getting-started/installation/"
    exit 1
fi

# Run tests based on type
run_test() {
    local test_name=$1
    local test_file=$2
    local extra_args="${3:-}"
    
    echo -e "${YELLOW}Running ${test_name}...${NC}"
    echo ""
    
    if k6 run "$test_file" $extra_args; then
        echo -e "${GREEN}✓ ${test_name} completed successfully${NC}"
        return 0
    else
        echo -e "${RED}✗ ${test_name} failed${NC}"
        return 1
    fi
}

case "$TEST_TYPE" in
    smoke)
        run_test "Smoke Test" "$(dirname "$0")/smoke-test.js"
        ;;
    load)
        run_test "API Load Test" "$(dirname "$0")/api-load-test.js"
        ;;
    stress)
        run_test "Stress Test" "$(dirname "$0")/stress-test.js"
        ;;
    spike)
        run_test "Spike Test" "$(dirname "$0")/spike-test.js"
        ;;
    soak)
        echo -e "${YELLOW}Note: Soak test runs for 30 minutes by default${NC}"
        run_test "Soak Test" "$(dirname "$0")/soak-test.js"
        ;;
    all)
        echo -e "${YELLOW}Running all tests in sequence...${NC}"
        echo ""
        
        FAILED=0
        
        run_test "Smoke Test" "$(dirname "$0")/smoke-test.js" || FAILED=1
        echo ""
        
        if [ $FAILED -eq 0 ]; then
            run_test "API Load Test" "$(dirname "$0")/api-load-test.js" || FAILED=1
            echo ""
        fi
        
        if [ $FAILED -eq 0 ]; then
            run_test "Stress Test" "$(dirname "$0")/stress-test.js" || FAILED=1
            echo ""
        fi
        
        if [ $FAILED -eq 0 ]; then
            run_test "Spike Test" "$(dirname "$0")/spike-test.js" || FAILED=1
            echo ""
        fi
        
        if [ $FAILED -eq 0 ]; then
            echo -e "${GREEN}All tests completed successfully!${NC}"
        else
            echo -e "${RED}Some tests failed. Check the results above.${NC}"
            exit 1
        fi
        ;;
    quick)
        # Quick validation - smoke + short load test
        run_test "Smoke Test" "$(dirname "$0")/smoke-test.js"
        echo ""
        run_test "Quick Load Test" "$(dirname "$0")/api-load-test.js" "--vus 10 --duration 1m"
        ;;
    *)
        echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
        echo ""
        echo "Usage: $0 [smoke|load|stress|spike|soak|all|quick]"
        echo ""
        echo "Test Types:"
        echo "  smoke   - Quick verification (30s, 1 VU)"
        echo "  load    - Normal load test (~16m, 10-100 VUs)"
        echo "  stress  - Find breaking points (~23m, 10-300 VUs)"
        echo "  spike   - Sudden traffic spikes (~5m, 10-500 VUs)"
        echo "  soak    - Memory leak detection (30m, 50 VUs)"
        echo "  all     - Run all tests in sequence"
        echo "  quick   - Smoke + short load test for CI"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}Results saved to: ${RESULTS_DIR}${NC}"




