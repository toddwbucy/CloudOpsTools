#!/bin/bash
# PCM-Ops Tools Unified Startup Script
# Starts the integrated FastAPI backend serving both API and web interface

set -e  # Exit on error

# Don't add local bin to PATH to avoid Poetry version conflicts
# export PATH="$HOME/.local/bin:$PATH"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PATH="$PROJECT_ROOT/backend"
LOGS_PATH="$PROJECT_ROOT/logs"

# Default log level and mode
LOG_LEVEL="info"
DEV_MODE="false"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            DEV_MODE="true"
            echo -e "${YELLOW}⚠️  DEVELOPMENT MODE ENABLED ⚠️${NC}"
            echo -e "${YELLOW}AWS operations will be mocked and use dev database${NC}"
            shift
            ;;
        --debug)
            LOG_LEVEL="debug"
            shift
            ;;
        --log-level=*)
            LOG_LEVEL="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dev] [--debug] [--log-level=LEVEL]"
            exit 1
            ;;
    esac
done

# Function to check if a port is in use
is_port_in_use() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        return 0
    else
        return 1
    fi
}

# Function to set up logging directory
setup_logging() {
    # Create logs directory if it doesn't exist
    mkdir -p "$LOGS_PATH"
    
    # Create timestamped log file
    TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
    LOG_FILE="$LOGS_PATH/cloudopstools_$TIMESTAMP.log"

    # Create symlink to latest log
    ln -sf "cloudopstools_$TIMESTAMP.log" "$LOGS_PATH/cloudopstools.log"

    # Rotate old logs (keep last 10)
    find "$LOGS_PATH" -name "cloudopstools_*.log" | sort -r | tail -n +11 | xargs --no-run-if-empty rm
    
    echo -e "${GREEN}Logging set up in $LOGS_PATH${NC}"
}

# Print header
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}    PCM-Ops Tools Unified Application      ${NC}"
echo -e "${BLUE}============================================${NC}"

# Check if Poetry is installed and dependencies are available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Error: Poetry is not installed${NC}"
    echo -e "${YELLOW}Install Poetry first: curl -sSL https://install.python-poetry.org | python3 -${NC}"
    exit 1
fi

# Check if Poetry can run Python in the virtual environment
# Make sure we're in the project root for Poetry
cd "$PROJECT_ROOT"

# Try to run a simple Python command through Poetry
if ! poetry run python -c "import sys; print(sys.executable)" &>/dev/null; then
    echo -e "${RED}Error: Poetry environment not properly configured${NC}"
    echo -e "${YELLOW}Run 'poetry install' to set up the environment${NC}"
    exit 1
fi

echo -e "${GREEN}Using Poetry environment...${NC}"

# Check if port is already in use
if is_port_in_use 8500; then
    echo -e "${RED}Error: Port 8500 is already in use${NC}"
    echo -e "${YELLOW}Stop the existing service or use a different port${NC}"
    exit 1
fi

# Set up logging
setup_logging

# Set PYTHONPATH to include the project root for proper imports
export PYTHONPATH="$PROJECT_ROOT"

# Set development mode and database (always use production database)
if [ "$DEV_MODE" = "true" ]; then
    export DEV_MODE=true
    echo -e "${YELLOW}DEV_MODE enabled (mocks AWS operations but uses main database)${NC}"
else
    export DEV_MODE=false
fi

# Always use the main production database
export DATABASE_URL="sqlite:///./data/cloudopstools.db"
echo -e "${GREEN}Using main database: data/cloudopstools.db${NC}"

# Set log level for the application
if [ "$LOG_LEVEL" = "debug" ]; then
    UVICORN_LOG_LEVEL="debug"
    export DEBUG=true
else
    UVICORN_LOG_LEVEL="info"
    export DEBUG=false
fi

# Start the unified application
echo -e "${GREEN}Starting PCM-Ops Tools...${NC}"

cd "$PROJECT_ROOT"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting PCM-Ops Tools with log level: $UVICORN_LOG_LEVEL" > "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Current directory: $(pwd)" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Poetry version: $(poetry --version)" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Poetry env: $(poetry env info --path)" >> "$LOG_FILE"

# Configure uvicorn flags based on mode
if [ "$DEV_MODE" = "true" ]; then
    RELOAD_FLAG="--reload"
    echo -e "${YELLOW}Using --reload flag in development mode${NC}"
else
    RELOAD_FLAG=""
    echo -e "${GREEN}Running in production mode (no --reload)${NC}"
fi

# Run the application
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running: poetry run uvicorn backend.main:app --host 0.0.0.0 --port 8500 --log-level $UVICORN_LOG_LEVEL $RELOAD_FLAG" >> "$LOG_FILE"
poetry run uvicorn backend.main:app --host 0.0.0.0 --port 8500 --log-level "$UVICORN_LOG_LEVEL" $RELOAD_FLAG >> "$LOG_FILE" 2>&1 &

APP_PID=$!

# Wait for application to start
echo -e "${YELLOW}Waiting for application to start...${NC}"
sleep 3

# Check if application is running
if ps -p $APP_PID > /dev/null; then
    echo -e "${GREEN}Application started successfully (PID: $APP_PID)${NC}"
else
    echo -e "${RED}Failed to start application. Check $LOG_FILE for details${NC}"
    exit 1
fi

# Create PID file for cleanup
echo "$APP_PID" > "$PROJECT_ROOT/.running_pid"

# Save log file path
echo "Application log: $LOG_FILE" > "$PROJECT_ROOT/.log_path"

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}PCM-Ops Tools is running!${NC}"
echo -e "${YELLOW}Web interface: ${NC}http://localhost:8500"
echo -e "${YELLOW}API documentation: ${NC}http://localhost:8500/docs"
echo -e "${YELLOW}AWS Script Runner: ${NC}http://localhost:8500/aws/script-runner"
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}Log file: ${NC}$LOG_FILE"
echo -e "${BLUE}============================================${NC}"
echo -e "${YELLOW}To stop the application, run: ./stop.sh${NC}"
echo -e "${BLUE}============================================${NC}"

# Keep script running to enable easy termination with Ctrl+C
echo -e "${YELLOW}Press Ctrl+C to stop the application...${NC}"
trap "echo -e '${RED}Stopping application...${NC}' && kill $APP_PID 2>/dev/null" INT
wait