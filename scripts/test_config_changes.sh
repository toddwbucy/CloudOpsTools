#!/bin/bash
# =============================================================================
# Configuration Change Verification Script
# =============================================================================
# This script verifies that rate limit configuration changes from .env apply
# without code modification.
#
# Usage: ./scripts/test_config_changes.sh
#
# Prerequisites:
#   1. Server NOT running (script will start/stop it)
#   2. poetry installed
#   3. Ports 8500 and 8501 available
#
# What this script does:
#   1. Starts server with default rate limits (10/minute auth)
#   2. Verifies auth endpoint hits limit at 10 requests
#   3. Stops server
#   4. Creates .env with modified rate limit (3/minute auth)
#   5. Restarts server
#   6. Verifies auth endpoint now hits limit at 3 requests
#   7. Cleans up
# =============================================================================

set -e

# Configuration
HOST="${HOST:-localhost}"
PORT="${PORT:-8500}"
BASE_URL="http://${HOST}:${PORT}"
ENV_FILE=".env"
ENV_BACKUP=".env.backup"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"

    # Kill server if running
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    # Restore original .env if backup exists
    if [[ -f "$ENV_BACKUP" ]]; then
        mv "$ENV_BACKUP" "$ENV_FILE"
        echo "Restored original .env"
    elif [[ -f "$ENV_FILE" ]] && [[ "$CREATED_ENV" == "true" ]]; then
        rm -f "$ENV_FILE"
        echo "Removed test .env"
    fi

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT

# Check if server is already running
check_server_not_running() {
    if curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" 2>/dev/null | grep -q "200"; then
        echo -e "${RED}ERROR: Server already running at ${BASE_URL}${NC}"
        echo "Please stop the server before running this test."
        exit 1
    fi
}

# Start server in background
start_server() {
    echo -e "${YELLOW}Starting server...${NC}"
    poetry run uvicorn backend.main:app --host 0.0.0.0 --port "$PORT" &
    SERVER_PID=$!

    # Wait for server to start (max 30 seconds)
    for i in {1..30}; do
        if curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" 2>/dev/null | grep -q "200"; then
            echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"
            return 0
        fi
        sleep 1
    done

    echo -e "${RED}ERROR: Server failed to start within 30 seconds${NC}"
    return 1
}

# Stop server
stop_server() {
    echo -e "${YELLOW}Stopping server...${NC}"
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null || true
        echo -e "${GREEN}Server stopped${NC}"
    fi
    SERVER_PID=""

    # Wait for port to be released
    sleep 2
}

# Count requests until rate limit
count_until_rate_limit() {
    local endpoint="$1"
    local max_requests="${2:-20}"
    local method="${3:-POST}"
    local payload="${4:-}"

    local count=0
    for i in $(seq 1 "$max_requests"); do
        local http_code
        if [[ "$method" == "POST" ]] && [[ -n "$payload" ]]; then
            http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST "$endpoint" \
                -H "Content-Type: application/json" \
                -d "$payload")
        else
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint")
        fi

        if [[ "$http_code" == "429" ]]; then
            echo "$count"
            return 0
        fi
        count=$((count + 1))
    done

    # No rate limit hit
    echo "$count"
    return 1
}

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   Configuration Change Verification Test${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Check server not running
check_server_not_running

# Backup existing .env if present
CREATED_ENV="false"
if [[ -f "$ENV_FILE" ]]; then
    cp "$ENV_FILE" "$ENV_BACKUP"
    echo "Backed up existing .env"
fi

# =============================================================================
# Phase 1: Test with default configuration (10/minute auth)
# =============================================================================
echo ""
echo -e "${BLUE}PHASE 1: Testing with default rate limits${NC}"
echo "Default auth limit: 10/minute"
echo ""

# Remove any .env to use defaults
rm -f "$ENV_FILE"

# Start server with defaults
if ! start_server; then
    exit 1
fi

# Test auth endpoint with default limits
AUTH_ENDPOINT="${BASE_URL}/api/auth/aws-credentials"
AUTH_PAYLOAD='{"access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","environment":"com"}'

echo ""
echo "Sending requests to auth endpoint until rate limited..."
DEFAULT_COUNT=$(count_until_rate_limit "$AUTH_ENDPOINT" 15 "POST" "$AUTH_PAYLOAD" || echo "15+")

echo -e "Requests before rate limit: ${GREEN}${DEFAULT_COUNT}${NC}"

if [[ "$DEFAULT_COUNT" == "10" ]]; then
    echo -e "${GREEN}PASS: Default rate limit of 10/minute is working${NC}"
else
    echo -e "${YELLOW}NOTE: Expected 10, got ${DEFAULT_COUNT} (may be affected by previous tests)${NC}"
fi

# Stop server
stop_server

# =============================================================================
# Phase 2: Test with modified configuration (3/minute auth)
# =============================================================================
echo ""
echo -e "${BLUE}PHASE 2: Testing with modified rate limits${NC}"
echo "New auth limit: 3/minute"
echo ""

# Create .env with modified rate limit
cat > "$ENV_FILE" << 'EOF'
# Modified rate limit for testing configuration changes
RATE_LIMIT_AUTH_ENDPOINTS=3/minute
RATE_LIMIT_EXECUTION_ENDPOINTS=5/minute
RATE_LIMIT_READ_ENDPOINTS=100/minute
EOF
CREATED_ENV="true"

echo "Created .env with RATE_LIMIT_AUTH_ENDPOINTS=3/minute"
echo ""

# Start server with modified config
if ! start_server; then
    exit 1
fi

# Verify config in health endpoint
echo "Verifying configuration in health endpoint..."
HEALTH_RESPONSE=$(curl -s "${BASE_URL}/api/health")
if echo "$HEALTH_RESPONSE" | grep -q "3/minute"; then
    echo -e "${GREEN}Health endpoint shows new rate limit: 3/minute${NC}"
else
    echo -e "${YELLOW}Health response: ${HEALTH_RESPONSE}${NC}"
fi

# Test auth endpoint with new limits
echo ""
echo "Sending requests to auth endpoint until rate limited..."
MODIFIED_COUNT=$(count_until_rate_limit "$AUTH_ENDPOINT" 10 "POST" "$AUTH_PAYLOAD" || echo "10+")

echo -e "Requests before rate limit: ${GREEN}${MODIFIED_COUNT}${NC}"

# =============================================================================
# Results
# =============================================================================
echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   TEST RESULTS${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

PASSED=true

if [[ "$MODIFIED_COUNT" == "3" ]]; then
    echo -e "${GREEN}PASS: Modified rate limit of 3/minute is working${NC}"
else
    echo -e "${RED}FAIL: Expected rate limit at 3 requests, got ${MODIFIED_COUNT}${NC}"
    PASSED=false
fi

if [[ "$DEFAULT_COUNT" != "$MODIFIED_COUNT" ]]; then
    echo -e "${GREEN}PASS: Configuration change took effect (${DEFAULT_COUNT} -> ${MODIFIED_COUNT})${NC}"
else
    echo -e "${RED}FAIL: Rate limit did not change between default and modified${NC}"
    PASSED=false
fi

echo ""
if $PASSED; then
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}   CONFIGURATION CHANGE VERIFICATION PASSED${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo ""
    echo "Verified that:"
    echo "  1. Rate limits can be configured via .env file"
    echo "  2. Changes apply after server restart"
    echo "  3. No code modification required"
else
    echo -e "${RED}=============================================${NC}"
    echo -e "${RED}   CONFIGURATION CHANGE VERIFICATION FAILED${NC}"
    echo -e "${RED}=============================================${NC}"
    exit 1
fi
