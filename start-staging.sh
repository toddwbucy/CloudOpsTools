#!/bin/bash

# PCM-Ops Tools - Staging Environment Startup Script
# This script starts the application in staging mode for safe testing

set -e  # Exit on any error

echo "🚀 Starting PCM-Ops Tools in STAGING mode..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if staging environment file exists
if [ ! -f ".env.staging" ]; then
    echo -e "${RED}❌ .env.staging file not found!${NC}"
    echo "Please create .env.staging file with staging configuration"
    exit 1
fi

# Backup current .env if it exists
if [ -f ".env" ]; then
    echo -e "${YELLOW}📝 Backing up current .env to .env.backup${NC}"
    cp .env .env.backup
fi

# Copy staging environment
echo -e "${BLUE}🔧 Setting up staging environment...${NC}"
cp .env.staging .env

# Check if Poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}❌ Poetry not found! Please install Poetry first.${NC}"
    exit 1
fi

# Install dependencies if needed
echo -e "${BLUE}📦 Checking dependencies...${NC}"
poetry install --no-interaction

# Create staging database directory
mkdir -p data
mkdir -p logs

# Initialize staging database
echo -e "${BLUE}🗄️ Initializing staging database...${NC}"
DATABASE_URL="sqlite:///./data/pcm_ops_tools_staging.db" poetry run python backend/db/init_db.py

# Check if staging database was created
if [ ! -f "data/pcm_ops_tools_staging.db" ]; then
    echo -e "${RED}❌ Failed to create staging database!${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Staging database initialized${NC}"

# Start the application on staging port
echo -e "${GREEN}🚀 Starting application on staging port 8501...${NC}"
echo -e "${YELLOW}📍 Staging URL: http://localhost:8501${NC}"
echo -e "${YELLOW}📍 API Docs: http://localhost:8501/docs${NC}"
echo -e "${YELLOW}📍 Feature Flags: http://localhost:8501/api/feature-flags${NC}"
echo ""
echo -e "${BLUE}Feature Flag Management:${NC}"
echo "  • GET  /api/feature-flags/health - System health"
echo "  • GET  /api/feature-flags - List all flags"
echo "  • POST /api/feature-flags/toggle - Toggle flags"
echo "  • POST /api/feature-flags/emergency-rollback - Emergency disable all"
echo ""
echo -e "${YELLOW}🔧 All feature flags start DISABLED for safety${NC}"
echo -e "${YELLOW}🔧 Enable flags one by one for testing${NC}"
echo ""

# Function to handle cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down staging environment...${NC}"
    
    # Restore original .env if backup exists
    if [ -f ".env.backup" ]; then
        echo -e "${BLUE}🔄 Restoring original .env file${NC}"
        mv .env.backup .env
    else
        echo -e "${YELLOW}⚠️  No .env backup found, removing staging .env${NC}"
        rm -f .env
    fi
    
    echo -e "${GREEN}✅ Staging cleanup complete${NC}"
    exit 0
}

# Set up cleanup on script exit
trap cleanup EXIT INT TERM

# Start the application
poetry run uvicorn backend.main:app \
    --host "0.0.0.0" \
    --port 8501 \
    --reload \
    --log-level debug \
    --access-log