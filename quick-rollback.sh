#!/bin/bash
# quick-rollback.sh - Emergency rollback automation
# Usage: ./quick-rollback.sh <feature_flag_name>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FEATURE_NAME=$1
BASE_URL=${2:-"http://localhost:8500"}

if [ -z "$FEATURE_NAME" ]; then
    echo -e "${RED}❌ Usage: ./quick-rollback.sh <feature_flag_name> [base_url]${NC}"
    echo ""
    echo "Examples:"
    echo "  ./quick-rollback.sh new_secret_key_handling"
    echo "  ./quick-rollback.sh xss_protection_enabled http://localhost:8501"
    echo ""
    exit 1
fi

echo -e "${RED}🚨 EMERGENCY ROLLBACK: $FEATURE_NAME${NC}"
echo -e "${BLUE}Time: $(date)${NC}"
echo -e "${BLUE}URL: $BASE_URL${NC}"

# Log rollback to file
echo "[$(date)] ROLLBACK INITIATED - Feature: $FEATURE_NAME" >> rollback.log

# Check if API is responding
echo -e "${YELLOW}🔍 Checking API availability...${NC}"
if ! curl -s "$BASE_URL/api/health" > /dev/null; then
    echo -e "${RED}❌ API not responding at $BASE_URL${NC}"
    echo -e "${YELLOW}Consider manual application restart${NC}"
    exit 1
fi

echo -e "${GREEN}✅ API is responding${NC}"

# Get current feature flag status
echo -e "${YELLOW}🔍 Checking current flag status...${NC}"
CURRENT_STATUS=$(curl -s "$BASE_URL/api/feature-flags/$FEATURE_NAME" 2>/dev/null || echo "")

if [ -n "$CURRENT_STATUS" ]; then
    echo -e "${BLUE}Current status: $CURRENT_STATUS${NC}"
else
    echo -e "${YELLOW}⚠️  Could not retrieve current status${NC}"
fi

# Disable the feature flag
echo -e "${YELLOW}🔄 Disabling feature flag...${NC}"
ROLLBACK_RESPONSE=$(curl -s -X POST "$BASE_URL/api/feature-flags/toggle" \
  -H "Content-Type: application/json" \
  -d "{\"flag_name\": \"$FEATURE_NAME\", \"enabled\": false}" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to send rollback request${NC}"
    echo -e "${YELLOW}Attempting emergency rollback of all flags...${NC}"
    
    # Try emergency rollback all
    curl -s -X POST "$BASE_URL/api/feature-flags/emergency-rollback" > /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Emergency rollback of all flags completed${NC}"
    else
        echo -e "${RED}❌ Emergency rollback failed - manual intervention required${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ Rollback request sent${NC}"
fi

# Wait a moment for the change to take effect
sleep 2

# Verify rollback
echo -e "${YELLOW}🧪 Verifying rollback...${NC}"
VERIFICATION=$(curl -s "$BASE_URL/api/feature-flags/$FEATURE_NAME" 2>/dev/null)

if [ -n "$VERIFICATION" ]; then
    STATUS=$(echo "$VERIFICATION" | grep -o '"enabled":[^,]*' | cut -d':' -f2 | tr -d ' ')
    if [ "$STATUS" = "false" ]; then
        echo -e "${GREEN}✅ ROLLBACK SUCCESSFUL${NC}"
        echo -e "${GREEN}Feature $FEATURE_NAME is now disabled${NC}"
    else
        echo -e "${YELLOW}⚠️  ROLLBACK STATUS UNCLEAR${NC}"
        echo -e "${BLUE}Response: $VERIFICATION${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Could not verify rollback status${NC}"
fi

# Test critical functionality
echo -e "${YELLOW}🧪 Testing critical paths...${NC}"

# Health check
if curl -s "$BASE_URL/api/health" > /dev/null; then
    echo -e "${GREEN}✅ Application health check passed${NC}"
else
    echo -e "${RED}❌ Application health check failed${NC}"
    echo -e "${YELLOW}Consider emergency application restart${NC}"
fi

# Authentication endpoints
if curl -s "$BASE_URL/api/auth/aws-credentials" > /dev/null; then
    echo -e "${GREEN}✅ Authentication endpoints responding${NC}"
else
    echo -e "${YELLOW}⚠️  Authentication endpoints may be affected${NC}"
fi

# Provider endpoints
if curl -s "$BASE_URL/api/providers" > /dev/null; then
    echo -e "${GREEN}✅ Provider endpoints responding${NC}"
else
    echo -e "${YELLOW}⚠️  Provider endpoints may be affected${NC}"
fi

# Web interface
if curl -s "$BASE_URL/" > /dev/null; then
    echo -e "${GREEN}✅ Web interface responding${NC}"
else
    echo -e "${YELLOW}⚠️  Web interface may be affected${NC}"
fi

echo ""
echo -e "${BLUE}📊 Rollback Summary:${NC}"
echo -e "${BLUE}Feature: $FEATURE_NAME${NC}"
echo -e "${BLUE}Time: $(date)${NC}"
echo -e "${BLUE}Status: Check messages above${NC}"

# Log completion
echo "[$(date)] ROLLBACK COMPLETED - Feature: $FEATURE_NAME" >> rollback.log

echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "1. Monitor application logs: tail -f logs/pcm_ops_tools.log"
echo "2. Test user workflows manually"
echo "3. Check rollback.log for audit trail"
echo "4. Document incident and root cause"
echo ""
echo -e "${BLUE}For additional help, see: docs/Rollback-Procedures.md${NC}"