#!/bin/bash
# PCM-Ops Tools Unified Stop Script
# Stops the integrated FastAPI application

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$PROJECT_ROOT/.running_pid"

# Print header
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}    Stopping PCM-Ops Tools                 ${NC}"
echo -e "${BLUE}============================================${NC}"

# Function to kill process by port
kill_process_by_port() {
    local port=$1
    local service_name=$2
    
    # Get PID using the port
    local pid=$(lsof -ti :$port 2>/dev/null)
    
    if [ -n "$pid" ]; then
        echo -e "${YELLOW}Stopping $service_name on port $port (PID: $pid)...${NC}"
        kill $pid 2>/dev/null
        
        # Wait for process to terminate
        for i in {1..5}; do
            if ! ps -p $pid > /dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        
        if ! ps -p $pid > /dev/null 2>&1; then
            echo -e "${GREEN}$service_name stopped successfully.${NC}"
            return 0
        else
            echo -e "${RED}$service_name did not stop gracefully. Forcing termination...${NC}"
            kill -9 $pid 2>/dev/null
            sleep 1
            if ! ps -p $pid > /dev/null 2>&1; then
                echo -e "${GREEN}$service_name terminated successfully.${NC}"
                return 0
            else
                echo -e "${RED}Failed to terminate $service_name.${NC}"
                return 1
            fi
        fi
    else
        echo -e "${YELLOW}No process found using port $port.${NC}"
        return 0
    fi
}

# Try to stop service using PID file
if [ -f "$PID_FILE" ]; then
    APP_PID=$(cat "$PID_FILE")
    
    if ps -p $APP_PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping application (PID: $APP_PID)...${NC}"
        kill $APP_PID
        
        # Wait for process to stop
        count=0
        while ps -p $APP_PID > /dev/null 2>&1 && [ $count -lt 10 ]; do
            sleep 1
            count=$((count + 1))
        done
        
        # Force kill if still running
        if ps -p $APP_PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Force stopping application...${NC}"
            kill -9 $APP_PID
        fi
        
        echo -e "${GREEN}Application stopped${NC}"
    else
        echo -e "${YELLOW}Application not running (PID: $APP_PID not found)${NC}"
    fi
    
    # Clean up PID file
    rm -f "$PID_FILE"
else
    echo -e "${YELLOW}No PID file found. Will try to find service by port.${NC}"
    # Try to stop by port
    echo -e "${BLUE}Checking for application on port 8500...${NC}"
    kill_process_by_port 8500 "PCM-Ops Tools"
fi

# Also try to find and stop any running uvicorn processes
echo -e "${BLUE}Checking for any remaining uvicorn processes...${NC}"
PIDS=$(pgrep -f "uvicorn backend.main:app")
if [ ! -z "$PIDS" ]; then
    echo -e "${YELLOW}Found running processes: $PIDS${NC}"
    echo -e "${YELLOW}Stopping processes...${NC}"
    kill $PIDS
    sleep 2
    
    # Check if any still running
    PIDS=$(pgrep -f "uvicorn backend.main:app")
    if [ ! -z "$PIDS" ]; then
        echo -e "${YELLOW}Force stopping processes...${NC}"
        kill -9 $PIDS
    fi
    
    echo -e "${GREEN}Processes stopped${NC}"
fi

# Clean up log path file
rm -f "$PROJECT_ROOT/.log_path"

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}PCM-Ops Tools stopped successfully!${NC}"
echo -e "${BLUE}============================================${NC}"
