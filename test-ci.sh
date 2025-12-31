#!/bin/bash
# CI/CD Integration Script for PCM-Ops Tools Testing
# Optimized for continuous integration environments

set -e

# Configuration
CI_MODE=true
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_REPORTS_DIR="${PROJECT_ROOT}/test-reports"
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-80}
MAX_TEST_TIME=${MAX_TEST_TIME:-600}  # 10 minutes max

# Colors (only if not in CI)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

log_info() {
    echo -e "${BLUE}[CI-INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[CI-SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[CI-WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[CI-ERROR]${NC} $1"
}

# Ensure we're in the project root
cd "$PROJECT_ROOT"

# Create reports directory
mkdir -p "$TEST_REPORTS_DIR"

# Start timer
START_TIME=$(date +%s)

log_info "Starting CI test suite for PCM-Ops Tools"
log_info "Coverage threshold: ${COVERAGE_THRESHOLD}%"
log_info "Max test time: ${MAX_TEST_TIME}s"

# Check environment
log_info "Environment check:"
echo "  Python version: $(python3 --version 2>/dev/null || echo 'Not found')"
echo "  Poetry version: $(poetry --version 2>/dev/null || echo 'Not found')"
echo "  Git branch: $(git branch --show-current 2>/dev/null || echo 'Not a git repo')"
echo "  Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"

# Install dependencies with timeout
log_info "Installing dependencies..."
timeout 300 poetry install --no-interaction || {
    log_error "Dependency installation timed out or failed"
    exit 1
}

# Set up test database
log_info "Setting up test database..."
export DATABASE_URL="sqlite:///./data/pcm_ops_tools_ci_test.db"
poetry run python backend/db/init_db.py || {
    log_error "Database initialization failed"
    exit 1
}

# Function to run tests with timeout
run_tests_with_timeout() {
    local test_cmd="$1"
    local test_name="$2"
    local timeout_duration="$3"
    
    log_info "Running $test_name..."
    
    if timeout "$timeout_duration" bash -c "$test_cmd"; then
        log_success "$test_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "$test_name timed out after ${timeout_duration}s"
        else
            log_error "$test_name failed with exit code $exit_code"
        fi
        return $exit_code
    fi
}

# Track test results
TOTAL_PHASES=0
PASSED_PHASES=0
FAILED_PHASES=()

# Phase 1: Code Quality Checks
log_info "Phase 1: Code Quality Checks"
((TOTAL_PHASES++))

code_quality_cmd="poetry run black --check backend/ && poetry run isort --check-only backend/ && poetry run ruff check backend/"
if run_tests_with_timeout "$code_quality_cmd" "Code Quality" 60; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Code Quality")
fi

# Phase 2: Type Checking
log_info "Phase 2: Type Checking"
((TOTAL_PHASES++))

type_check_cmd="poetry run mypy backend/"
if run_tests_with_timeout "$type_check_cmd" "Type Checking" 120; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Type Checking")
fi

# Phase 3: Unit Tests with Coverage
log_info "Phase 3: Unit Tests with Coverage"
((TOTAL_PHASES++))

unit_test_cmd="poetry run pytest tests/unit/ -m unit --cov=backend --cov-report=xml:${TEST_REPORTS_DIR}/unit-coverage.xml --cov-report=term-missing --junit-xml=${TEST_REPORTS_DIR}/unit-results.xml -v"
if run_tests_with_timeout "$unit_test_cmd" "Unit Tests" 180; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Unit Tests")
fi

# Phase 4: Integration Tests
log_info "Phase 4: Integration Tests"
((TOTAL_PHASES++))

integration_test_cmd="poetry run pytest tests/integration/ -m integration --junit-xml=${TEST_REPORTS_DIR}/integration-results.xml -v"
if run_tests_with_timeout "$integration_test_cmd" "Integration Tests" 240; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Integration Tests")
fi

# Phase 5: Security Tests
log_info "Phase 5: Security Tests"
((TOTAL_PHASES++))

security_test_cmd="poetry run pytest tests/security/ -m security --junit-xml=${TEST_REPORTS_DIR}/security-results.xml -v"
if run_tests_with_timeout "$security_test_cmd" "Security Tests" 120; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Security Tests")
fi

# Phase 6: Full Test Suite (Quick Mode)
log_info "Phase 6: Full Test Suite (Quick Mode)"
((TOTAL_PHASES++))

full_test_cmd="poetry run pytest tests/ -m 'not slow' --cov=backend --cov-report=xml:${TEST_REPORTS_DIR}/full-coverage.xml --junit-xml=${TEST_REPORTS_DIR}/full-results.xml --maxfail=5"
if run_tests_with_timeout "$full_test_cmd" "Full Test Suite" 300; then
    ((PASSED_PHASES++))
else
    FAILED_PHASES+=("Full Test Suite")
fi

# Coverage Analysis
log_info "Analyzing test coverage..."
if [ -f "${TEST_REPORTS_DIR}/full-coverage.xml" ]; then
    COVERAGE_PERCENT=$(poetry run coverage report --format=text 2>/dev/null | grep "^TOTAL" | awk '{print $4}' | sed 's/%//' || echo "0")
    
    if [ -n "$COVERAGE_PERCENT" ] && [ "$COVERAGE_PERCENT" -ge "$COVERAGE_THRESHOLD" ]; then
        log_success "Coverage requirement met: ${COVERAGE_PERCENT}%"
        COVERAGE_PASSED=true
    else
        log_warning "Coverage below threshold: ${COVERAGE_PERCENT}% (required: ${COVERAGE_THRESHOLD}%)"
        COVERAGE_PASSED=false
    fi
else
    log_warning "Coverage report not found"
    COVERAGE_PASSED=false
fi

# Calculate total time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

# Generate CI summary report
cat << EOF > "${TEST_REPORTS_DIR}/ci-summary.json"
{
  "timestamp": "$(date -Iseconds)",
  "duration_seconds": $TOTAL_TIME,
  "git_branch": "$(git branch --show-current 2>/dev/null || echo 'unknown')",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "total_phases": $TOTAL_PHASES,
  "passed_phases": $PASSED_PHASES,
  "failed_phases": $(echo "${FAILED_PHASES[@]}" | jq -R 'split(" ")' 2>/dev/null || echo '[]'),
  "coverage_percent": ${COVERAGE_PERCENT:-0},
  "coverage_threshold": $COVERAGE_THRESHOLD,
  "coverage_passed": $COVERAGE_PASSED,
  "reports_generated": [
    $(find "$TEST_REPORTS_DIR" -name "*.xml" -o -name "*.json" | sed 's/.*/"&"/' | paste -sd ',' || echo '')
  ]
}
EOF

# Generate human-readable summary
cat << EOF > "${TEST_REPORTS_DIR}/ci-summary.txt"
PCM-Ops Tools CI Test Summary
============================

Date: $(date)
Duration: ${TOTAL_TIME}s
Git Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')
Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')

Test Phases: $PASSED_PHASES/$TOTAL_PHASES passed

Coverage: ${COVERAGE_PERCENT:-0}% (threshold: ${COVERAGE_THRESHOLD}%)

Reports Generated:
$(find "$TEST_REPORTS_DIR" -name "*.xml" -o -name "*.json" | sort)

EOF

# Display results
echo "========================================"
log_info "CI Test Results Summary"
echo "========================================"
echo "Total Time: ${TOTAL_TIME}s"
echo "Test Phases: $PASSED_PHASES/$TOTAL_PHASES passed"
echo "Coverage: ${COVERAGE_PERCENT:-0}% (threshold: ${COVERAGE_THRESHOLD}%)"

if [ ${#FAILED_PHASES[@]} -eq 0 ] && [ "$COVERAGE_PASSED" = true ]; then
    log_success "✅ All CI tests passed! Build is ready for deployment."
    CI_EXIT_CODE=0
elif [ ${#FAILED_PHASES[@]} -eq 0 ] && [ "$COVERAGE_PASSED" = false ]; then
    log_warning "⚠️ Tests passed but coverage is below threshold."
    log_warning "Consider this a warning for now, but improve coverage."
    CI_EXIT_CODE=0  # Don't fail CI for coverage alone
else
    log_error "❌ CI tests failed!"
    echo ""
    echo "Failed phases:"
    for phase in "${FAILED_PHASES[@]}"; do
        echo "  • $phase"
    done
    echo ""
    echo "Check detailed reports in: $TEST_REPORTS_DIR"
    CI_EXIT_CODE=1
fi

# Cleanup
rm -f "./data/pcm_ops_tools_ci_test.db" 2>/dev/null || true

# Archive reports for CI systems
if [ -n "${CI_ARTIFACTS_DIR:-}" ]; then
    log_info "Copying reports to CI artifacts directory: $CI_ARTIFACTS_DIR"
    mkdir -p "$CI_ARTIFACTS_DIR"
    cp -r "$TEST_REPORTS_DIR"/* "$CI_ARTIFACTS_DIR/" 2>/dev/null || true
fi

# Output summary for CI systems
echo "::set-output name=test_phases_passed::$PASSED_PHASES"
echo "::set-output name=test_phases_total::$TOTAL_PHASES"
echo "::set-output name=coverage_percent::${COVERAGE_PERCENT:-0}"
echo "::set-output name=duration_seconds::$TOTAL_TIME"

exit $CI_EXIT_CODE