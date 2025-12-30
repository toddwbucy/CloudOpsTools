# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CloudOpsTools is a unified multi-cloud operations platform built with FastAPI. The application serves both REST API endpoints and a web interface from a single process on port 8500. It's designed for standardizing operations across AWS, Azure, GCP, and ServiceNow.

## Common Development Commands

### Initial Setup
```bash
./setup.sh              # Install Poetry and dependencies
```

### Running the Application
```bash
./start.sh              # Start the unified FastAPI application
./start.sh --dev        # Start with mock AWS operations and dev database
./start.sh --debug      # Start with debug logging
./stop.sh               # Stop the application
```

### Testing
```bash
# Run all tests
poetry run pytest -q

# Run specific test categories
poetry run pytest -m unit tests/unit/
poetry run pytest -m integration tests/integration/
poetry run pytest -m security tests/security/

# Run tests with coverage
poetry run pytest -q --cov=backend --cov-report=term-missing --cov-report=html:htmlcov

# Run single test file or function
poetry run pytest tests/unit/test_config.py
poetry run pytest tests/unit/test_config.py::test_specific_function -v

# Quick smoke tests (excludes slow tests)
poetry run pytest -m "not slow"

# Comprehensive test script
./run-tests.sh all      # All tests including code quality
./run-tests.sh unit     # Unit tests only
./run-tests.sh --coverage integration
```

### Code Quality
```bash
# Format code (run before commits)
poetry run black backend/
poetry run isort backend/

# Lint code
poetry run ruff check backend/
poetry run ruff check backend/ --fix

# Type checking
poetry run mypy backend/

# All quality checks in one command
poetry run black backend/ && poetry run isort backend/ && poetry run ruff check backend/
```

### Database Operations
```bash
# Initialize database
poetry run python backend/db/init_db.py

# Development database (separate from main)
DATABASE_URL="sqlite:///./data/cloudopstools_dev.db" poetry run python backend/db/init_db.py
```

## Architecture

### Unified FastAPI Application

The platform uses a single FastAPI process ([backend/main.py](backend/main.py)) that serves:
- REST API endpoints at `/api/*`
- Web UI at `/aws/*`, `/azure/*`, `/servicenow/*`
- Static files at `/static/*`
- API documentation at `/docs`

Key architectural components:
- **Provider Discovery**: Dynamic registration of provider routers from [backend/providers/](backend/providers/)
- **Security Middleware**: XSS, CSRF, and encryption layers in [backend/core/security.py](backend/core/security.py)
- **Session Management**: Server-side sessions with optional encryption via [backend/core/utils/session_store.py](backend/core/utils/session_store.py)
- **Feature Flags**: Safe rollout controls in [backend/core/feature_flags.py](backend/core/feature_flags.py)

### Provider-Based Structure

Tools are organized by cloud provider under `backend/providers/{provider}/{tool}/`:
```
backend/providers/aws/script_runner/
├── __init__.py         # Exports routers for auto-discovery
├── api/                # FastAPI route handlers
├── services/           # Business logic
├── schemas/            # Pydantic models
└── types/              # Type definitions
```

**Provider Discovery Mechanism**: The `discover_provider_routers()` function in [backend/providers/\_\_init\_\_.py](backend/providers/__init__.py) automatically:
1. Scans `backend/providers/` for subdirectories (providers)
2. For each provider, looks for tool modules with a `routers` export
3. Registers routers with the FastAPI app at `/api/{provider}/{tool}`
4. Makes tools available via `/api/providers` endpoint

To add a new tool:
1. Create `backend/providers/{provider}/{tool}/__init__.py`
2. Define routers as: `routers = [(router, "/path/to/api")]`
3. The tool will be auto-discovered on startup

### Database Layer

- **ORM**: SQLAlchemy 2.0 with declarative models in [backend/db/models/](backend/db/models/)
- **SQLite Compatibility**: Uses `func.json_extract()` for JSON queries - requires SQLite with JSON1 extension
- **Important Pattern**: SQLAlchemy 2.0 uses `func.json_extract()` instead of older JSON operations:
  ```python
  # Correct SQLAlchemy 2.0 pattern
  func.json_extract(Execution.execution_metadata, '$.qc_step')
  func.cast(func.json_extract(Execution.execution_metadata, '$.change_id'), Integer)
  ```

### Security Features (Feature-Flagged)

All Phase 1 security features are controlled by environment variables:
- `FEATURE_FLAG_NEW_SECRET_KEY_HANDLING=enabled` - Auto-generated secure keys
- `FEATURE_FLAG_XSS_PROTECTION_ENABLED=enabled` - Input validation and CSP headers
- `FEATURE_FLAG_CSRF_TOKENS_ENABLED=enabled` - CSRF token protection
- `FEATURE_FLAG_SECURE_CREDENTIAL_STORAGE=enabled` - Encrypted session credentials
- `FEATURE_FLAG_STRUCTURED_LOGGING=enabled` - Security-focused structured logs

Feature flags enable safe rollouts and rollbacks. Check [backend/core/feature_flags.py](backend/core/feature_flags.py) before modifying security-related code.

### AWS Script Runner Architecture

The Script Runner ([backend/providers/aws/script\_runner/](backend/providers/aws/script_runner/)) is a complex multi-account AWS automation tool:

**Key Services**:
- **OrgVisitor**: Traverses AWS Organizations hierarchy to discover accounts
- **EC2Manager**: Discovers EC2 instances across accounts and regions
- **SSMExecutor**: Executes scripts via AWS Systems Manager
- **ExecutionStateManager**: Tracks execution state and results

**Execution Flow**:
1. User submits change with target criteria (account IDs, tags, regions)
2. System discovers matching EC2 instances across accounts
3. Scripts execute via SSM with state tracking
4. Results collected and stored in database with JSON metadata

**Important**: The web UI for Script Runner was removed. Functionality is now accessed through specialized tools like Linux QC Patching.

## Python Version and OS Support

- **Python**: 3.11+ (documented requirement)
- **Supported OS**: Ubuntu, Debian, BunsenLabs
- **Setup script**: Handles OS detection and Python installation
- See [docs/adr/infrastructure-compatibility-improvements.md](docs/adr/infrastructure-compatibility-improvements.md) for rationale

## Configuration Files

- **pyproject.toml**: Poetry dependencies, tool configuration (Black, isort, mypy, ruff, pytest)
- **.env**: Environment configuration (copy from `.env.example`)
- **pytest.ini**: Test configuration and markers
- **backend/core/config.py**: Application settings with Pydantic validation

## Testing Strategy

**Test Markers** (defined in [pyproject.toml](pyproject.toml)):
- `@pytest.mark.unit` - Fast isolated tests
- `@pytest.mark.integration` - Tests requiring running application
- `@pytest.mark.security` - Security-focused tests
- `@pytest.mark.critical` - Critical path tests
- `@pytest.mark.slow` - Long-running tests
- `@pytest.mark.feature_flag` - Tests requiring feature flags

**Test Structure**:
- `tests/unit/` - Unit tests for individual components
- `tests/integration/` - API endpoint and service integration tests
- `tests/security/` - Authentication and data protection tests
- `tests/conftest.py` - Shared fixtures and test configuration

## Important Development Patterns

### AWS Credential Management

Credentials are managed through [backend/providers/aws/common/services/credential\_manager.py](backend/providers/aws/common/services/credential_manager.py):
- Supports both COM (commercial) and GOV (GovCloud) environments
- Credentials can be provided via environment variables or web UI
- Session-based credential storage with encryption (when feature flag enabled)
- Automatic validation and expiration handling

### Template System

Templates use Jinja2 in [backend/templates/](backend/templates/) with custom globals:
- `csrf_token()` - Generate CSRF tokens for forms
- `csp_nonce()` - Get current CSP nonce for inline scripts
- `get_flashed_messages()` - Flask-compatible message flashing (stub)

### URL Redirects for Backward Compatibility

[backend/main.py](backend/main.py) includes redirects from old URLs to new ones:
```python
/aws/linux-patcher → /aws/linux-qc-patching-prep
/aws/linux-qc-prep → /aws/linux-qc-patching-prep
/aws/linux-qc-post → /aws/linux-qc-patching-post
```

Maintain these redirects when renaming tools to avoid breaking existing integrations.

## Common Pitfalls

1. **SQLite JSON Support**: Always use `func.json_extract()` for JSON queries. The setup script verifies SQLite JSON1 extension support.

2. **Provider Discovery**: Tools must export `routers` list in `__init__.py` to be auto-discovered. Format: `routers = [(router_instance, "/api/path")]`

3. **Security Middleware Order**: In [backend/main.py](backend/main.py), middleware is added in reverse order of execution. Security headers must be added before CSRF protection.

4. **Feature Flag Checks**: Always check if feature flags are enabled before applying security features:
   ```python
   from backend.core.feature_flags import is_feature_enabled
   if is_feature_enabled('XSS_PROTECTION_ENABLED'):
       # Apply XSS protection
   ```

5. **Session Management**: Sessions are server-side stored in database. Don't store large objects in session - use credential manager for AWS credentials.

6. **DEV_MODE**: When `--dev` flag is used, AWS operations are mocked. Useful for development without AWS credentials.

## Access Points

- **Web Interface**: http://localhost:8500
- **API Documentation**: http://localhost:8500/docs
- **Health Check**: http://localhost:8500/api/health
- **Feature Flags**: http://localhost:8500/api/feature-flags
- **Providers List**: http://localhost:8500/api/providers

## Development Workflow

1. Make changes to code
2. Run code formatters: `poetry run black backend/ && poetry run isort backend/`
3. Run linter: `poetry run ruff check backend/ --fix`
4. Run tests: `poetry run pytest -q`
5. Test in browser at http://localhost:8500 (start with `./start.sh`)
6. Commit changes (formatters and linters should pass before committing)

## Logging

Application uses structured logging via loguru ([backend/core/utils/logging\_config.py](backend/core/utils/logging_config.py)):
- Application logs: `logs/app.log`
- Security logs: `logs/security.log`
- Standard logger names: `cloudopstools.{module}`

Enable debug logging with `./start.sh --debug`
