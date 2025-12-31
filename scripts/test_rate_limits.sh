#!/bin/bash
# =============================================================================
# Rate Limit Manual Testing Script
# =============================================================================
# This script tests all three rate limit tiers to verify they work correctly.
# Run this after starting the server with: poetry run uvicorn backend.main:app --reload --port 8500
#
# Usage: ./scripts/test_rate_limits.sh [--host HOST] [--port PORT]
#
# Test coverage:
#   1. Auth endpoints: 10 requests/minute limit
#   2. Execution endpoints: 5 requests/minute limit
#   3. Read endpoints: 100 requests/minute limit
#   4. Retry-After header verification
#   5. Graceful degradation (app continues serving after rate limit)
# =============================================================================

set -e

# Default values
HOST="${HOST:-localhost}"
PORT="${PORT:-8500}"
BASE_URL="http://${HOST}:${PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            BASE_URL="http://${HOST}:${PORT}"
            shift 2
            ;;
        --port)
            PORT="$2"
            BASE_URL="http://${HOST}:${PORT}"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   Rate Limit Manual Testing Script${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo -e "Target: ${GREEN}${BASE_URL}${NC}"
echo ""

# Check if server is running
echo -e "${YELLOW}Checking server connectivity...${NC}"
if ! curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" | grep -q "200"; then
    echo -e "${RED}ERROR: Server not responding at ${BASE_URL}${NC}"
    echo "Start the server with: poetry run uvicorn backend.main:app --reload --port 8500"
    exit 1
fi
echo -e "${GREEN}Server is running!${NC}"
echo ""

# =============================================================================
# Test 1: Auth Endpoint Rate Limit (10/minute)
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}TEST 1: Auth Endpoint Rate Limit (10/min)${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Testing POST /api/auth/aws-credentials..."
echo "Expected: First 10 requests succeed, 11th returns HTTP 429"
echo ""

AUTH_ENDPOINT="${BASE_URL}/api/auth/aws-credentials"
AUTH_PAYLOAD='{"access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","environment":"com"}'

FOUND_429=false
for i in $(seq 1 12); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${AUTH_ENDPOINT}" \
        -H "Content-Type: application/json" \
        -d "${AUTH_PAYLOAD}")

    if [[ "$HTTP_CODE" == "429" ]]; then
        echo -e "Request ${i}: ${RED}HTTP ${HTTP_CODE} (Rate Limited)${NC}"
        FOUND_429=true

        # Verify Retry-After header
        RETRY_AFTER=$(curl -s -I -X POST "${AUTH_ENDPOINT}" \
            -H "Content-Type: application/json" \
            -d "${AUTH_PAYLOAD}" 2>/dev/null | grep -i "retry-after" | cut -d: -f2 | tr -d ' \r')

        if [[ -n "$RETRY_AFTER" ]]; then
            echo -e "${GREEN}Retry-After header present: ${RETRY_AFTER} seconds${NC}"
        else
            echo -e "${YELLOW}WARNING: Retry-After header not found${NC}"
        fi
        break
    else
        echo "Request ${i}: HTTP ${HTTP_CODE}"
    fi
done

if $FOUND_429; then
    echo -e "\n${GREEN}PASS: Auth endpoint rate limit working correctly${NC}"
else
    echo -e "\n${RED}FAIL: Did not hit rate limit after 12 requests${NC}"
fi
echo ""

# Wait a bit for limits to partially reset
sleep 2

# =============================================================================
# Test 2: Execution Endpoint Rate Limit (5/minute)
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}TEST 2: Execution Endpoint Rate Limit (5/min)${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Testing POST /api/tools/1/execute..."
echo "Expected: First 5 requests succeed, 6th returns HTTP 429"
echo ""

EXEC_ENDPOINT="${BASE_URL}/api/tools/1/execute"

FOUND_429=false
for i in $(seq 1 7); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${EXEC_ENDPOINT}" \
        -H "Content-Type: application/json")

    if [[ "$HTTP_CODE" == "429" ]]; then
        echo -e "Request ${i}: ${RED}HTTP ${HTTP_CODE} (Rate Limited)${NC}"
        FOUND_429=true

        # Verify Retry-After header
        RETRY_AFTER=$(curl -s -I -X POST "${EXEC_ENDPOINT}" \
            -H "Content-Type: application/json" 2>/dev/null | grep -i "retry-after" | cut -d: -f2 | tr -d ' \r')

        if [[ -n "$RETRY_AFTER" ]]; then
            echo -e "${GREEN}Retry-After header present: ${RETRY_AFTER} seconds${NC}"
        else
            echo -e "${YELLOW}WARNING: Retry-After header not found${NC}"
        fi
        break
    else
        echo "Request ${i}: HTTP ${HTTP_CODE}"
    fi
done

if $FOUND_429; then
    echo -e "\n${GREEN}PASS: Execution endpoint rate limit working correctly${NC}"
else
    echo -e "\n${RED}FAIL: Did not hit rate limit after 7 requests${NC}"
fi
echo ""

# Wait a bit for limits to partially reset
sleep 2

# =============================================================================
# Test 3: Read Endpoint Rate Limit (100/minute)
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}TEST 3: Read Endpoint Rate Limit (100/min)${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Testing GET /api/tools/..."
echo "Expected: First 100 requests succeed, 101st returns HTTP 429"
echo ""

READ_ENDPOINT="${BASE_URL}/api/tools/"

# For read endpoint, we need to make 101 requests
# Show progress every 10 requests
FOUND_429=false
for i in $(seq 1 103); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X GET "${READ_ENDPOINT}")

    if [[ "$HTTP_CODE" == "429" ]]; then
        echo -e "Request ${i}: ${RED}HTTP ${HTTP_CODE} (Rate Limited)${NC}"
        FOUND_429=true

        # Verify Retry-After header
        RETRY_AFTER=$(curl -s -I -X GET "${READ_ENDPOINT}" 2>/dev/null | grep -i "retry-after" | cut -d: -f2 | tr -d ' \r')

        if [[ -n "$RETRY_AFTER" ]]; then
            echo -e "${GREEN}Retry-After header present: ${RETRY_AFTER} seconds${NC}"
        else
            echo -e "${YELLOW}WARNING: Retry-After header not found${NC}"
        fi
        break
    else
        # Only show every 10th request and the last few
        if [[ $((i % 20)) -eq 0 ]] || [[ $i -gt 95 ]]; then
            echo "Request ${i}: HTTP ${HTTP_CODE}"
        fi
    fi
done

if $FOUND_429; then
    echo -e "\n${GREEN}PASS: Read endpoint rate limit working correctly${NC}"
else
    echo -e "\n${RED}FAIL: Did not hit rate limit after 103 requests${NC}"
fi
echo ""

# =============================================================================
# Test 4: Graceful Degradation
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}TEST 4: Graceful Degradation${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Testing that app continues serving other endpoints after rate limit..."
echo ""

# Test that health endpoint still works after rate limiting
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/health")
if [[ "$HEALTH_CODE" == "200" ]]; then
    echo -e "${GREEN}PASS: /api/health still responding (HTTP ${HEALTH_CODE})${NC}"
else
    echo -e "${RED}FAIL: /api/health not responding correctly (HTTP ${HEALTH_CODE})${NC}"
fi

# Test a different tool ID (should be a fresh endpoint)
TOOL2_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/tools/2")
if [[ "$TOOL2_CODE" == "200" ]] || [[ "$TOOL2_CODE" == "429" ]]; then
    echo -e "${GREEN}PASS: /api/tools/2 still responding (HTTP ${TOOL2_CODE})${NC}"
else
    echo -e "${RED}FAIL: /api/tools/2 not responding correctly (HTTP ${TOOL2_CODE})${NC}"
fi
echo ""

# =============================================================================
# Test 5: Health Endpoint Rate Limiting Metrics
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}TEST 5: Health Endpoint Rate Limiting Metrics${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Checking /api/health for rate limiting configuration..."
echo ""

HEALTH_RESPONSE=$(curl -s "${BASE_URL}/api/health")
echo "Response:"
echo "${HEALTH_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${HEALTH_RESPONSE}"
echo ""

# Check for rate_limiting in response
if echo "${HEALTH_RESPONSE}" | grep -q "rate_limiting"; then
    echo -e "${GREEN}PASS: Rate limiting metrics present in health endpoint${NC}"
else
    echo -e "${RED}FAIL: Rate limiting metrics not found in health endpoint${NC}"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   TEST SUMMARY${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Manual verification complete."
echo ""
echo "To reset rate limits, either:"
echo "  1. Wait for the time window to reset (60 seconds)"
echo "  2. Restart the server"
echo ""
echo -e "For more detailed testing, run: ${YELLOW}poetry run pytest tests/test_rate_limiting.py -v${NC}"
echo ""
