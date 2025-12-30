#!/bin/bash
# PCM-Ops Tools Main Setup Script
# This script sets up both backend and frontend dependencies using Poetry

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: This script should not be run as root.${NC}"
    echo -e "${YELLOW}Please run this script as a regular user (not with sudo).${NC}"
    echo -e "${YELLOW}If you need to install system packages, the script will prompt for sudo when needed.${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect operating system${NC}"
    exit 1
fi

echo -e "${BLUE}Detected OS: $OS $OS_VERSION${NC}"

# Validate supported OS
if [[ "$OS" != "ubuntu" && "$OS" != "debian" && "$OS" != "bunsenlabs" ]]; then
    echo -e "${RED}Unsupported operating system: $OS${NC}"
    echo -e "${YELLOW}This script only supports Ubuntu, Debian, and BunsenLabs${NC}"
    exit 1
fi

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}       PCM-Ops Tools Setup Script          ${NC}"
echo -e "${BLUE}============================================${NC}"

# Check if Python 3.11 is installed
echo -e "${BLUE}Checking Python 3.11 installation...${NC}"
if ! python3.11 --version &> /dev/null; then
    echo -e "${RED}Python 3.11 is not installed.${NC}"
    echo -e "${YELLOW}Installing Python 3.11 for $OS...${NC}"
    
    # Update package lists
    sudo apt update || {
        echo -e "${RED}Failed to update package lists${NC}"
        exit 1
    }
    
    if [[ "$OS" == "ubuntu" ]]; then
        # Ubuntu: Use deadsnakes PPA
        echo -e "${BLUE}Installing software-properties-common for Ubuntu...${NC}"
        sudo apt install -y software-properties-common || {
            echo -e "${RED}Failed to install software-properties-common${NC}"
            exit 1
        }
        
        echo -e "${BLUE}Adding deadsnakes PPA for Ubuntu...${NC}"
        sudo add-apt-repository ppa:deadsnakes/ppa -y || {
            echo -e "${RED}Failed to add deadsnakes PPA${NC}"
            exit 1
        }
        
        # Update package lists again
        sudo apt update || {
            echo -e "${RED}Failed to update package lists after adding PPA${NC}"
            exit 1
        }
        
        # Install Python 3.11
        sudo apt install -y python3.11 python3.11-venv python3.11-dev || {
            echo -e "${RED}Failed to install Python 3.11${NC}"
            exit 1
        }
        
    elif [[ "$OS" == "debian" || "$OS" == "bunsenlabs" ]]; then
        # Debian/BunsenLabs: Check if Python 3.11 is available in repositories
        echo -e "${BLUE}Checking Python 3.11 availability in $OS repositories...${NC}"
        
        if apt-cache search python3.11 | grep -q "python3.11"; then
            echo -e "${BLUE}Installing Python 3.11 from $OS repositories...${NC}"
            sudo apt install -y python3.11 python3.11-venv python3.11-dev || {
                echo -e "${RED}Failed to install Python 3.11 from $OS repositories${NC}"
                exit 1
            }
        else
            # For older versions or if not available, use system python3
            echo -e "${YELLOW}Python 3.11 not available in standard $OS repositories${NC}"
            echo -e "${YELLOW}Attempting to use system Python 3...${NC}"
            
            # Check if system python3 is at least 3.10 (minimum for union syntax)
            PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            if python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
                echo -e "${GREEN}✓ System Python $PYTHON_VERSION is compatible (3.10+ required)${NC}"
                # Install venv and dev packages for system python
                sudo apt install -y python3-venv python3-dev || {
                    echo -e "${YELLOW}Warning: Could not install python3-venv or python3-dev${NC}"
                }
            else
                echo -e "${RED}System Python $PYTHON_VERSION is too old (3.10+ required)${NC}"
                exit 1
            fi
        fi
    fi
    
    echo -e "${GREEN}✓ Python installed successfully${NC}"
else
    echo -e "${GREEN}✓ Python 3.11 is already installed${NC}"
fi

# Check if SQLite3 is installed and has JSON support
echo -e "${BLUE}Checking SQLite3 installation and JSON support...${NC}"
if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}SQLite3 is not installed.${NC}"
    echo -e "${YELLOW}Installing SQLite3...${NC}"
    
    sudo apt update || {
        echo -e "${RED}Failed to update package lists${NC}"
        exit 1
    }
    
    sudo apt install -y sqlite3 libsqlite3-dev || {
        echo -e "${RED}Failed to install SQLite3${NC}"
        exit 1
    }
    
    echo -e "${GREEN}✓ SQLite3 installed successfully${NC}"
else
    echo -e "${GREEN}✓ SQLite3 is already installed${NC}"
fi

# Verify SQLite3 has JSON support (required for the application)
echo -e "${BLUE}Verifying SQLite3 JSON support...${NC}"
if sqlite3 :memory: "SELECT json_extract('{\"test\": \"value\"}', '$.test');" 2>/dev/null | grep -q "value"; then
    echo -e "${GREEN}✓ SQLite3 JSON support is working${NC}"
else
    echo -e "${YELLOW}Warning: SQLite3 JSON support test failed${NC}"
    echo -e "${YELLOW}The application may not work correctly${NC}"
    echo -e "${YELLOW}Consider upgrading SQLite3 to version 3.9 or higher${NC}"
fi

# Check if ~/bin directory exists and is in PATH
echo -e "${BLUE}Checking ~/bin directory and PATH...${NC}"
BIN_DIR="$HOME/bin"
PATH_UPDATED=false

# Create ~/bin directory if it doesn't exist
if [ ! -d "$BIN_DIR" ]; then
    echo -e "${YELLOW}Creating ~/bin directory...${NC}"
    mkdir -p "$BIN_DIR" || {
        echo -e "${RED}Failed to create ~/bin directory${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Created ~/bin directory${NC}"
fi

# Check if ~/bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Adding ~/bin to PATH in ~/.bashrc...${NC}"
    
    # Add ~/bin to PATH in ~/.bashrc if not already there
    if ! grep -q "export PATH=\"\$HOME/bin:\$PATH\"" ~/.bashrc; then
        {
            echo ''
            echo '# Add ~/bin to PATH for local binaries'
            echo "export PATH=\"\$HOME/bin:\$PATH\""
        } >> ~/.bashrc
        echo -e "${GREEN}✓ Added ~/bin to PATH in ~/.bashrc${NC}"
        PATH_UPDATED=true
    else
        echo -e "${GREEN}✓ ~/bin already configured in ~/.bashrc${NC}"
    fi
    
    # Source ~/.bashrc to update current session
    if [ "$PATH_UPDATED" = true ]; then
        echo -e "${YELLOW}Sourcing ~/.bashrc to update current session...${NC}"
        export PATH="$HOME/bin:$PATH"
        echo -e "${GREEN}✓ PATH updated for current session${NC}"
    fi
else
    echo -e "${GREEN}✓ ~/bin is already in PATH${NC}"
fi

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Poetry is not installed.${NC}"
    echo -e "${YELLOW}Installing Poetry...${NC}"
    curl -sSL https://install.python-poetry.org | python3 -
    
    # Add Poetry to PATH for current session
    export PATH="$HOME/.local/bin:$PATH"
    
    # Check again
    if ! command -v poetry &> /dev/null; then
        echo -e "${RED}Failed to install Poetry. Please install it manually:${NC}"
        echo "curl -sSL https://install.python-poetry.org | python3 -"
        echo "or visit: https://python-poetry.org/docs/#installation"
        exit 1
    fi
    echo -e "${GREEN}✓ Poetry installed successfully${NC}"
fi

# Function to download file with error handling
download_file() {
    local url=$1
    local output=$2
    local description=$3
    
    echo -e "${YELLOW}Downloading ${description}...${NC}"
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "$output" || {
            echo -e "${RED}Failed to download ${description}${NC}"
            return 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$output" || {
            echo -e "${RED}Failed to download ${description}${NC}"
            return 1
        }
    else
        echo -e "${RED}Neither curl nor wget found. Please install one of them.${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ Downloaded ${description}${NC}"
}

# Clean up old venv if it exists
if [ -d "$PROJECT_ROOT/venv" ]; then
    echo -e "${YELLOW}Removing old venv directory...${NC}"
    rm -rf "$PROJECT_ROOT/venv"
    echo -e "${GREEN}✓ Old venv removed${NC}"
fi

# Remove any broken Poetry environments
echo -e "${BLUE}Cleaning up Poetry environments...${NC}"
poetry env remove --all 2>/dev/null || true
echo -e "${GREEN}✓ Poetry environments cleaned${NC}"

# Install dependencies using Poetry
echo -e "${BLUE}Installing dependencies with Poetry...${NC}"
cd "$PROJECT_ROOT"
poetry install

# Create necessary directories
echo -e "${BLUE}Creating necessary directories...${NC}"
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/data"

# Frontend Setup
echo -e "${BLUE}Setting up Frontend...${NC}"

# Create frontend static directories
mkdir -p "$PROJECT_ROOT/frontend/static/css"
mkdir -p "$PROJECT_ROOT/frontend/static/js"

# Download Bootstrap and dependencies
cd "$PROJECT_ROOT/frontend/static"

# Bootswatch Darkly theme (includes Bootstrap CSS)
download_file \
    "https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/darkly/bootstrap.min.css" \
    "css/bootstrap.min.css" \
    "Bootswatch Darkly theme"

# Bootstrap Bundle JS (includes Popper)
download_file \
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" \
    "js/bootstrap.bundle.min.js" \
    "Bootstrap Bundle JS"

# jQuery
download_file \
    "https://code.jquery.com/jquery-3.6.0.min.js" \
    "js/jquery-3.6.0.min.js" \
    "jQuery 3.6.0"

echo -e "${GREEN}✓ Frontend setup complete${NC}"

# Database Setup
echo -e "${BLUE}Setting up Database...${NC}"

# Check if alembic.ini exists before running migrations
if [ -f "$PROJECT_ROOT/backend/alembic.ini" ]; then
    cd "$PROJECT_ROOT/backend"
    echo -e "${YELLOW}Running database migrations...${NC}"
    poetry run alembic upgrade head
    echo -e "${GREEN}✓ Database migrations complete${NC}"
else
    echo -e "${YELLOW}Database migrations skipped (alembic.ini not found)${NC}"
    echo -e "${YELLOW}The application will create tables automatically on first run.${NC}"
fi

# Update poetry.lock file if needed
echo -e "${BLUE}Checking poetry.lock file...${NC}"
cd "$PROJECT_ROOT"
if poetry check &>/dev/null; then
    echo -e "${GREEN}✓ poetry.lock is up to date${NC}"
else
    echo -e "${YELLOW}Updating poetry.lock file...${NC}"
    poetry lock
    echo -e "${GREEN}✓ poetry.lock updated${NC}"
fi

# Final summary
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e ""
echo -e "${GREEN}🚀 Ready to start PCM-Ops Tools!${NC}"
echo -e ""
echo -e "${YELLOW}To start the application:${NC}"
echo -e "${GREEN}  ./start.sh${NC}"
echo -e ""
echo -e "${YELLOW}To start in development mode:${NC}"
echo -e "  ./start.sh --dev"
echo -e ""
echo -e "${YELLOW}To start in debug mode:${NC}"
echo -e "  ./start.sh --debug"
echo -e ""
echo -e "${YELLOW}To stop the application:${NC}"
echo -e "  ./stop.sh"
echo -e ""
echo -e "${BLUE}Once started, access the application at:${NC}"
echo -e "  ${GREEN}http://localhost:8500${NC}"
echo -e ""
echo -e "${BLUE}============================================${NC}"