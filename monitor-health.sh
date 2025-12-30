#!/bin/bash

# PCM-Ops Tools Health Monitoring Script
# Monitors application health and feature flag status during rollouts

set -e

# Configuration
BASE_URL=${1:-"http://localhost:8500"}
CHECK_INTERVAL=${2:-30}  # seconds
LOG_FILE="monitoring.log"
ALERT_THRESHOLD=3  # Failed checks before alert

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
FAILED_CHECKS=0
TOTAL_CHECKS=0

echo -e "${BLUE}🔍 PCM-Ops Tools Health Monitor${NC}"
echo -e "${BLUE}URL: $BASE_URL${NC}"
echo -e "${BLUE}Check Interval: ${CHECK_INTERVAL}s${NC}"
echo -e "${BLUE}Log File: $LOG_FILE${NC}"
echo -e "${BLUE}Started: $(date)${NC}"
echo ""

# Initialize log file
echo "[$(date)] Health monitoring started - URL: $BASE_URL" >> $LOG_FILE

# Function to log with timestamp
log_event() {
    echo "[$(date)] $1" >> $LOG_FILE
    echo -e "$1"
}

# Function to check application health
check_health() {
    local status_code
    local response_time
    local start_time=$(date +%s.%3N)
    
    status_code=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/api/health" --max-time 10 || echo "000")
    local end_time=$(date +%s.%3N)
    response_time=$(echo "$end_time - $start_time" | bc -l || echo "N/A")
    
    if [ "$status_code" = "200" ]; then
        log_event "${GREEN}✅ Health Check: OK (${response_time}s)${NC}"
        return 0
    else
        log_event "${RED}❌ Health Check: FAILED (HTTP $status_code)${NC}"
        return 1
    fi
}

# Function to check feature flags health
check_feature_flags() {
    local status_code
    local enabled_flags
    
    status_code=$(curl -s -w "%{http_code}" -o /tmp/ff_response.json "$BASE_URL/api/feature-flags/health" --max-time 10 || echo "000")
    
    if [ "$status_code" = "200" ]; then
        enabled_flags=$(grep -o '"enabled_flags":[0-9]*' /tmp/ff_response.json | cut -d':' -f2 || echo "N/A")
        rollback_mode=$(grep -o '"rollback_mode":[^,}]*' /tmp/ff_response.json | cut -d':' -f2 || echo "false")
        
        if [ "$rollback_mode" = "true" ]; then
            log_event "${YELLOW}⚠️  Feature Flags: ROLLBACK MODE ACTIVE (${enabled_flags} enabled)${NC}"
        else
            log_event "${GREEN}✅ Feature Flags: OK (${enabled_flags} enabled)${NC}"
        fi
        rm -f /tmp/ff_response.json
        return 0
    else
        log_event "${RED}❌ Feature Flags: FAILED (HTTP $status_code)${NC}"
        rm -f /tmp/ff_response.json
        return 1
    fi
}

# Function to check critical endpoints
check_critical_endpoints() {
    local endpoints=(
        "/api/providers"
        "/api/auth/aws-credentials"
        "/aws"
        "/aws/tools"
    )
    
    local failed=0
    
    for endpoint in "${endpoints[@]}"; do
        local status_code
        status_code=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL$endpoint" --max-time 10 || echo "000")
        
        if [ "$status_code" = "200" ]; then
            echo -e "  ${GREEN}✅ $endpoint${NC}"
        else
            echo -e "  ${RED}❌ $endpoint (HTTP $status_code)${NC}"
            log_event "${RED}Critical endpoint failed: $endpoint (HTTP $status_code)${NC}"
            ((failed++))
        fi
    done
    
    if [ $failed -eq 0 ]; then
        log_event "${GREEN}✅ Critical Endpoints: All OK${NC}"
        return 0
    else
        log_event "${RED}❌ Critical Endpoints: $failed failed${NC}"
        return 1
    fi
}

# Function to check database connectivity (indirect)
check_database() {
    local status_code
    status_code=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/api/providers" --max-time 10 || echo "000")
    
    if [ "$status_code" = "200" ]; then
        log_event "${GREEN}✅ Database: Connection OK${NC}"
        return 0
    else
        log_event "${RED}❌ Database: Connection issues suspected (HTTP $status_code)${NC}"
        return 1
    fi
}

# Function to check performance
check_performance() {
    local start_time=$(date +%s.%3N)
    curl -s "$BASE_URL/api/health" > /dev/null --max-time 10 || return 1
    local end_time=$(date +%s.%3N)
    local response_time=$(echo "$end_time - $start_time" | bc -l)
    
    # Check if response time is acceptable (< 2 seconds)
    if (( $(echo "$response_time < 2.0" | bc -l) )); then
        log_event "${GREEN}✅ Performance: Good (${response_time}s)${NC}"
        return 0
    elif (( $(echo "$response_time < 5.0" | bc -l) )); then
        log_event "${YELLOW}⚠️  Performance: Slow (${response_time}s)${NC}"
        return 0
    else
        log_event "${RED}❌ Performance: Very slow (${response_time}s)${NC}"
        return 1
    fi
}

# Function to send alert
send_alert() {
    local message="$1"
    log_event "${RED}🚨 ALERT: $message${NC}"
    
    # Here you could add email, Slack, or other alerting mechanisms
    # For now, just log and display prominently
    echo ""
    echo -e "${RED}================================${NC}"
    echo -e "${RED}🚨 ALERT: $message${NC}"
    echo -e "${RED}Time: $(date)${NC}"
    echo -e "${RED}Failed Checks: $FAILED_CHECKS${NC}"
    echo -e "${RED}Total Checks: $TOTAL_CHECKS${NC}"
    echo -e "${RED}================================${NC}"
    echo ""
}

# Function to run all checks
run_health_checks() {
    ((TOTAL_CHECKS++))
    local check_failed=0
    
    echo -e "${BLUE}--- Health Check #$TOTAL_CHECKS at $(date) ---${NC}"
    
    # Run all health checks
    check_health || ((check_failed++))
    check_feature_flags || ((check_failed++))
    check_critical_endpoints || ((check_failed++))
    check_database || ((check_failed++))
    check_performance || ((check_failed++))
    
    if [ $check_failed -gt 0 ]; then
        ((FAILED_CHECKS++))
        log_event "${YELLOW}⚠️  Check completed with $check_failed issues${NC}"
        
        # Send alert if threshold exceeded
        if [ $FAILED_CHECKS -ge $ALERT_THRESHOLD ]; then
            send_alert "Application health degraded - $FAILED_CHECKS consecutive failed checks"
        fi
    else
        FAILED_CHECKS=0  # Reset failure counter on success
        log_event "${GREEN}✅ All checks passed${NC}"
    fi
    
    echo ""
}

# Function to handle cleanup on exit
cleanup() {
    log_event "${BLUE}Health monitoring stopped${NC}"
    echo -e "${BLUE}📊 Monitoring Summary:${NC}"
    echo -e "${BLUE}Total Checks: $TOTAL_CHECKS${NC}"
    echo -e "${BLUE}Failed Check Cycles: $FAILED_CHECKS${NC}"
    echo -e "${BLUE}Log File: $LOG_FILE${NC}"
    exit 0
}

# Set up cleanup on script exit
trap cleanup EXIT INT TERM

# Main monitoring loop
while true; do
    run_health_checks
    sleep $CHECK_INTERVAL
done