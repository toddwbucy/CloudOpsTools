#!/bin/bash
# Comprehensive testing automation script for PCM-Ops Tools
# Supports different test modes and generates reports

set -e

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_REPORTS_DIR="${PROJECT_ROOT}/test-reports"
COVERAGE_THRESHOLD=80
PYTEST_WORKERS=$(nproc)

# Legacy support for old script interface
BASE_URL=${1:-"http://localhost:8500"}
LEGACY_TEST_TYPE=${2:-"all"}  # all, critical, unit, integration
STAGING_MODE=${3:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [TEST_TYPE]

Test automation script for PCM-Ops Tools

TEST_TYPE:
    unit        Run only unit tests (fast)
    integration Run only integration tests  
    security    Run only security tests
    all         Run all tests (default)
    quick       Run quick smoke tests
    ci          Run tests suitable for CI/CD

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Verbose output
    -c, --coverage      Generate coverage report
    -x, --fail-fast     Stop on first failure
    -k EXPRESSION       Only run tests matching expression
    --parallel          Run tests in parallel
    --html-report       Generate HTML test report
    --baseline          Run baseline performance tests
    --security-only     Run security tests with detailed output

Examples:
    $0 unit                    # Run unit tests only
    $0 --coverage all          # Run all tests with coverage
    $0 -x security             # Run security tests, stop on first failure
    $0 --parallel integration  # Run integration tests in parallel
    $0 ci                      # Run tests for CI/CD pipeline

Legacy Usage (for backward compatibility):
    $0 [BASE_URL] [TEST_TYPE] [STAGING_MODE]
    $0 http://localhost:8500 critical false

EOF
}

# Detect if this is legacy usage (old script interface)
if [[ $# -eq 3 ]] || [[ $1 =~ ^https?:// ]] || [[ $2 =~ ^(all|critical|unit|integration|security)$ ]]; then
    log_info "Using legacy test interface"
    echo -e "${BLUE}🧪 PCM-Ops Tools Test Suite (Legacy Mode)${NC}"
    echo -e "${BLUE}URL: $BASE_URL${NC}"
    echo -e "${BLUE}Test Type: $LEGACY_TEST_TYPE${NC}"
    echo -e "${BLUE}Staging Mode: $STAGING_MODE${NC}"
    echo -e "${BLUE}Started: $(date)${NC}"
    echo ""

# Test results tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
CRITICAL_FAILURES=()

# Function to log test results
log_test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    ((TESTS_RUN++))
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✅ $test_name${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ $test_name${NC}"
        if [ -n "$details" ]; then
            echo -e "${RED}   Details: $details${NC}"
        fi
        ((TESTS_FAILED++))
        CRITICAL_FAILURES+=("$test_name")
    fi
}

# Function to check if application is running
check_app_running() {
    echo -e "${BLUE}🔍 Checking if application is running...${NC}"
    
    if curl -s "$BASE_URL/api/health" > /dev/null 2>&1; then
        log_test_result "Application Running" "PASS"
        return 0
    else
        log_test_result "Application Running" "FAIL" "Cannot connect to $BASE_URL"
        echo -e "${YELLOW}💡 Try starting the application first:${NC}"
        echo "   ./start.sh"
        echo "   # or for staging:"
        echo "   ./start-staging.sh"
        return 1
    fi
}

# Function to run code quality checks
run_code_quality_tests() {
    echo -e "${BLUE}📝 Running Code Quality Tests...${NC}"
    
    # Check if Poetry is available
    if ! command -v poetry &> /dev/null; then
        log_test_result "Poetry Available" "FAIL" "Poetry not installed"
        return 1
    fi
    
    log_test_result "Poetry Available" "PASS"
    
    # Install dependencies
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"
    if poetry install --no-interaction > /dev/null 2>&1; then
        log_test_result "Dependencies Install" "PASS"
    else
        log_test_result "Dependencies Install" "FAIL" "Poetry install failed"
        return 1
    fi
    
    # Run Black formatting check
    echo -e "${YELLOW}🎨 Checking code formatting (Black)...${NC}"
    if poetry run black --check backend/ > /dev/null 2>&1; then
        log_test_result "Code Formatting (Black)" "PASS"
    else
        log_test_result "Code Formatting (Black)" "FAIL" "Run: poetry run black backend/"
    fi
    
    # Run import sorting check
    echo -e "${YELLOW}📥 Checking import sorting (isort)...${NC}"
    if poetry run isort --check-only backend/ > /dev/null 2>&1; then
        log_test_result "Import Sorting (isort)" "PASS"
    else
        log_test_result "Import Sorting (isort)" "FAIL" "Run: poetry run isort backend/"
    fi
    
    # Run linting
    echo -e "${YELLOW}🔍 Running linting (Ruff)...${NC}"
    if poetry run ruff check backend/ > /dev/null 2>&1; then
        log_test_result "Linting (Ruff)" "PASS"
    else
        log_test_result "Linting (Ruff)" "FAIL" "Run: poetry run ruff check backend/ --fix"
    fi
    
    # Run type checking
    echo -e "${YELLOW}🏷️  Running type checking (MyPy)...${NC}"
    if poetry run mypy backend/ > /dev/null 2>&1; then
        log_test_result "Type Checking (MyPy)" "PASS"
    else
        log_test_result "Type Checking (MyPy)" "FAIL" "Type errors found"
    fi
}

# Function to run unit tests
run_unit_tests() {
    echo -e "${BLUE}🧪 Running Unit Tests...${NC}"
    
    if [ -d "tests" ] && [ -n "$(find tests -name 'test_*.py' -o -name '*_test.py')" ]; then
        if poetry run pytest tests/ -v --tb=short > /dev/null 2>&1; then
            log_test_result "Unit Tests" "PASS"
        else
            log_test_result "Unit Tests" "FAIL" "Some unit tests failed"
        fi
    else
        log_test_result "Unit Tests" "SKIP" "No unit tests found"
    fi
}

# Function to run critical path tests
run_critical_path_tests() {
    echo -e "${BLUE}🛣️  Running Critical Path Tests...${NC}"
    
    # Use the test file we created
    if [ -f "tests/test_critical_paths.py" ]; then
        local test_args=""
        if [ "$STAGING_MODE" = "true" ]; then
            test_args="--staging"
        else
            test_args="--base-url=$BASE_URL"
        fi
        
        if poetry run python -m pytest tests/test_critical_paths.py $test_args -v > /dev/null 2>&1; then
            log_test_result "Critical Path Tests" "PASS"
        else
            log_test_result "Critical Path Tests" "FAIL" "Critical functionality broken"
        fi
    else
        # Run manual critical path checks
        run_manual_critical_checks
    fi
}

# Function to run manual critical checks
run_manual_critical_checks() {
    echo -e "${YELLOW}🔧 Running Manual Critical Checks...${NC}"
    
    # Health check
    if curl -s "$BASE_URL/api/health" | grep -q "healthy"; then
        log_test_result "Health Endpoint" "PASS"
    else
        log_test_result "Health Endpoint" "FAIL" "Health check failed"
    fi
    
    # Feature flags
    if curl -s "$BASE_URL/api/feature-flags/health" | grep -q "healthy"; then
        log_test_result "Feature Flags Endpoint" "PASS"
    else
        log_test_result "Feature Flags Endpoint" "FAIL" "Feature flags not working"
    fi
    
    # Web interface
    if curl -s "$BASE_URL/" | grep -q "PCM-Ops Tools"; then
        log_test_result "Web Interface" "PASS"
    else
        log_test_result "Web Interface" "FAIL" "Web interface not loading"
    fi
    
    # API documentation
    if curl -s "$BASE_URL/docs" > /dev/null 2>&1; then
        log_test_result "API Documentation" "PASS"
    else
        log_test_result "API Documentation" "FAIL" "API docs not accessible"
    fi
    
    # Providers endpoint
    if curl -s "$BASE_URL/api/providers" | grep -q "providers"; then
        log_test_result "Providers Endpoint" "PASS"
    else
        log_test_result "Providers Endpoint" "FAIL" "Providers endpoint failed"
    fi
    
    # AWS auth pages
    if curl -s "$BASE_URL/aws" | grep -q -i "aws"; then
        log_test_result "AWS Auth Pages" "PASS"
    else
        log_test_result "AWS Auth Pages" "FAIL" "AWS pages not loading"
    fi
}

# Function to run performance tests
run_performance_tests() {
    echo -e "${BLUE}⚡ Running Performance Tests...${NC}"
    
    # Health check response time
    local start_time=$(date +%s.%3N)
    curl -s "$BASE_URL/api/health" > /dev/null
    local end_time=$(date +%s.%3N)
    local response_time=$(echo "$end_time - $start_time" | bc -l)
    
    if (( $(echo "$response_time < 2.0" | bc -l) )); then
        log_test_result "Health Check Performance" "PASS" "${response_time}s"
    else
        log_test_result "Health Check Performance" "FAIL" "Too slow: ${response_time}s"
    fi
    
    # Feature flags response time
    start_time=$(date +%s.%3N)
    curl -s "$BASE_URL/api/feature-flags" > /dev/null
    end_time=$(date +%s.%3N)
    response_time=$(echo "$end_time - $start_time" | bc -l)
    
    if (( $(echo "$response_time < 3.0" | bc -l) )); then
        log_test_result "Feature Flags Performance" "PASS" "${response_time}s"
    else
        log_test_result "Feature Flags Performance" "FAIL" "Too slow: ${response_time}s"
    fi
    
    # Web page load time
    start_time=$(date +%s.%3N)
    curl -s "$BASE_URL/" > /dev/null
    end_time=$(date +%s.%3N)
    response_time=$(echo "$end_time - $start_time" | bc -l)
    
    if (( $(echo "$response_time < 5.0" | bc -l) )); then
        log_test_result "Web Page Performance" "PASS" "${response_time}s"
    else
        log_test_result "Web Page Performance" "FAIL" "Too slow: ${response_time}s"
    fi
}

# Function to run security checks
run_security_tests() {
    echo -e "${BLUE}🔒 Running Security Tests...${NC}"
    
    # Check for hardcoded secrets (basic check)
    if grep -r "secret.*=.*['\"][^'\"]*['\"]" backend/ --include="*.py" | grep -v "your-secret-key-here"; then
        log_test_result "No Hardcoded Secrets" "FAIL" "Potential secrets found in code"
    else
        log_test_result "No Hardcoded Secrets" "PASS"
    fi
    
    # Check HTTPS redirect in production
    if curl -I "$BASE_URL" 2>/dev/null | grep -q "Strict-Transport-Security"; then
        log_test_result "HTTPS Security Headers" "PASS"
    else
        log_test_result "HTTPS Security Headers" "SKIP" "Not in HTTPS mode"
    fi
    
    # Check session cookie security
    local cookie_response=$(curl -I "$BASE_URL/aws" 2>/dev/null | grep -i "set-cookie" || echo "")
    if echo "$cookie_response" | grep -q "HttpOnly"; then
        log_test_result "HttpOnly Cookies" "PASS"
    else
        log_test_result "HttpOnly Cookies" "FAIL" "Session cookies should be HttpOnly"
    fi
}

# Main test execution based on type (legacy mode)
case $LEGACY_TEST_TYPE in
    "critical")
        check_app_running || exit 1
        run_critical_path_tests
        ;;
    "unit")
        run_code_quality_tests
        run_unit_tests
        ;;
    "integration")
        check_app_running || exit 1
        run_critical_path_tests
        run_performance_tests
        ;;
    "security")
        check_app_running || exit 1
        run_security_tests
        ;;
    "all"|*)
        run_code_quality_tests
        check_app_running || exit 1
        run_critical_path_tests
        run_performance_tests
        run_security_tests
        run_unit_tests
        ;;
esac

# Test summary (legacy mode)
echo ""
echo -e "${BLUE}📊 Test Summary:${NC}"
echo -e "${BLUE}Tests Run: $TESTS_RUN${NC}"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Failed Tests:${NC}"
    for failure in "${CRITICAL_FAILURES[@]}"; do
        echo -e "${RED}  • $failure${NC}"
    done
    echo ""
    echo -e "${YELLOW}💡 Recommendations:${NC}"
    echo "1. Fix failing tests before deploying changes"
    echo "2. Consider rolling back if critical tests fail"
    echo "3. Check logs for detailed error information"
    echo "4. Run specific test categories: ./run-tests.sh [url] [critical|unit|integration|security]"
    
    exit 1
else
    echo ""
    echo -e "${GREEN}✅ All tests passed! System is ready.${NC}"
    exit 0
fi

else
    # New enhanced pytest-based interface
    log_info "Using enhanced pytest-based test interface"
    
    # Parse command line arguments
    VERBOSE=0
    COVERAGE=0
    FAIL_FAST=0
    PARALLEL=0
    HTML_REPORT=0
    BASELINE=0
    SECURITY_ONLY=0
    TEST_EXPRESSION=""
    TEST_TYPE="all"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -c|--coverage)
                COVERAGE=1
                shift
                ;;
            -x|--fail-fast)
                FAIL_FAST=1
                shift
                ;;
            -k)
                TEST_EXPRESSION="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL=1
                shift
                ;;
            --html-report)
                HTML_REPORT=1
                shift
                ;;
            --baseline)
                BASELINE=1
                shift
                ;;
            --security-only)
                SECURITY_ONLY=1
                TEST_TYPE="security"
                shift
                ;;
            unit|integration|security|all|quick|ci)
                TEST_TYPE="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Ensure we're in the project root
    cd "$PROJECT_ROOT"

    # Create test reports directory
    mkdir -p "$TEST_REPORTS_DIR"

    # Check if poetry is available
    if ! command -v poetry &> /dev/null; then
        log_error "Poetry is not installed. Please install Poetry first."
        exit 1
    fi

    # Install test dependencies
    log_info "Installing test dependencies..."
    poetry install --with dev

    # Build pytest command
    PYTEST_CMD="poetry run pytest"

    # Add verbosity
    if [[ $VERBOSE -eq 1 ]]; then
        PYTEST_CMD="$PYTEST_CMD -v"
    else
        PYTEST_CMD="$PYTEST_CMD -q"
    fi

    # Add fail fast
    if [[ $FAIL_FAST -eq 1 ]]; then
        PYTEST_CMD="$PYTEST_CMD -x"
    fi

    # Add test expression filter
    if [[ -n "$TEST_EXPRESSION" ]]; then
        PYTEST_CMD="$PYTEST_CMD -k \"$TEST_EXPRESSION\""
    fi

    # Add parallel execution
    if [[ $PARALLEL -eq 1 ]] && [[ $PYTEST_WORKERS -gt 1 ]]; then
        PYTEST_CMD="$PYTEST_CMD -n $PYTEST_WORKERS"
        log_info "Running tests in parallel with $PYTEST_WORKERS workers"
    fi

    # Add coverage reporting
    if [[ $COVERAGE -eq 1 ]]; then
        PYTEST_CMD="$PYTEST_CMD --cov=backend --cov-report=term-missing --cov-report=xml:$TEST_REPORTS_DIR/coverage.xml"
        if [[ $HTML_REPORT -eq 1 ]]; then
            PYTEST_CMD="$PYTEST_CMD --cov-report=html:$TEST_REPORTS_DIR/htmlcov"
        fi
    fi

    # Add HTML report
    if [[ $HTML_REPORT -eq 1 ]]; then
        PYTEST_CMD="$PYTEST_CMD --html=$TEST_REPORTS_DIR/report.html --self-contained-html"
    fi

    # Configure test markers based on test type
    case $TEST_TYPE in
        "unit")
            PYTEST_CMD="$PYTEST_CMD -m unit tests/unit/"
            log_info "Running unit tests..."
            ;;
        "integration")
            PYTEST_CMD="$PYTEST_CMD -m integration tests/integration/"
            log_info "Running integration tests..."
            ;;
        "security")
            if [[ $SECURITY_ONLY -eq 1 ]]; then
                PYTEST_CMD="$PYTEST_CMD -m security tests/security/ -v --tb=short"
            else
                PYTEST_CMD="$PYTEST_CMD -m security tests/security/"
            fi
            log_info "Running security tests..."
            ;;
        "quick")
            PYTEST_CMD="$PYTEST_CMD -m \"not slow\" tests/unit/ tests/integration/"
            log_info "Running quick smoke tests..."
            ;;
        "ci")
            PYTEST_CMD="$PYTEST_CMD -m \"not slow\" --cov=backend --cov-report=xml:$TEST_REPORTS_DIR/coverage.xml tests/"
            log_info "Running CI/CD test suite..."
            ;;
        "all")
            PYTEST_CMD="$PYTEST_CMD tests/"
            log_info "Running all tests..."
            ;;
        *)
            log_error "Unknown test type: $TEST_TYPE"
            exit 1
            ;;
    esac

    # Run baseline performance tests if requested
    if [[ $BASELINE -eq 1 ]]; then
        log_info "Running baseline performance tests..."
        poetry run pytest -m baseline tests/ --benchmark-only --benchmark-json="$TEST_REPORTS_DIR/benchmark.json" || true
    fi

    # Set up test database
    log_info "Setting up test database..."
    export DATABASE_URL="sqlite:///./data/pcm_ops_tools_test.db"
    poetry run python backend/db/init_db.py

    # Run the tests
    log_info "Executing test command: $PYTEST_CMD"
    echo "----------------------------------------"

    # Execute pytest with error handling
    if eval "$PYTEST_CMD"; then
        TEST_EXIT_CODE=0
        log_success "Tests completed successfully!"
    else
        TEST_EXIT_CODE=$?
        log_error "Tests failed with exit code $TEST_EXIT_CODE"
    fi

    echo "----------------------------------------"

    # Coverage threshold check
    if [[ $COVERAGE -eq 1 ]]; then
        log_info "Checking coverage threshold ($COVERAGE_THRESHOLD%)..."
        
        # Extract coverage percentage from coverage report
        if [[ -f "$TEST_REPORTS_DIR/coverage.xml" ]]; then
            COVERAGE_PERCENT=$(poetry run coverage report --format=text | grep "^TOTAL" | awk '{print $4}' | sed 's/%//' || echo "0")
            
            if [[ -n "$COVERAGE_PERCENT" ]] && [[ $(echo "$COVERAGE_PERCENT >= $COVERAGE_THRESHOLD" | bc -l) -eq 1 ]]; then
                log_success "Coverage threshold met: ${COVERAGE_PERCENT}%"
            else
                log_warning "Coverage below threshold: ${COVERAGE_PERCENT}% (required: ${COVERAGE_THRESHOLD}%)"
                if [[ $TEST_TYPE == "ci" ]]; then
                    TEST_EXIT_CODE=1
                fi
            fi
        fi
    fi

    # Generate summary report
    cat << EOF > "$TEST_REPORTS_DIR/test-summary.txt"
PCM-Ops Tools Test Run Summary
=============================

Date: $(date)
Test Type: $TEST_TYPE
Exit Code: $TEST_EXIT_CODE
Coverage Enabled: $([[ $COVERAGE -eq 1 ]] && echo "Yes" || echo "No")
Parallel Execution: $([[ $PARALLEL -eq 1 ]] && echo "Yes ($PYTEST_WORKERS workers)" || echo "No")

Command Executed:
$PYTEST_CMD

Reports Generated:
$(find "$TEST_REPORTS_DIR" -name "*.xml" -o -name "*.html" -o -name "*.json" | sort)

EOF

    # Display final results
    if [[ $TEST_EXIT_CODE -eq 0 ]]; then
        log_success "All tests passed! 🎉"
        
        if [[ $HTML_REPORT -eq 1 ]]; then
            log_info "HTML report available at: $TEST_REPORTS_DIR/report.html"
        fi
        
        if [[ $COVERAGE -eq 1 ]] && [[ -d "$TEST_REPORTS_DIR/htmlcov" ]]; then
            log_info "Coverage report available at: $TEST_REPORTS_DIR/htmlcov/index.html"
        fi
    else
        log_error "Some tests failed. Check the output above for details."
        log_info "Test summary: $TEST_REPORTS_DIR/test-summary.txt"
    fi

    # Cleanup test database
    rm -f "./data/pcm_ops_tools_test.db" 2>/dev/null || true

    exit $TEST_EXIT_CODE
fi