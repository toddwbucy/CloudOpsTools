# Specification: API Rate Limiting Implementation

## Overview

Implement comprehensive API rate limiting for the CloudOpsTools FastAPI backend to prevent abuse, ensure service stability during high load, and protect against DoS attacks. This is a critical production security requirement currently identified as technical debt. The implementation will use SlowAPI to provide configurable, tiered rate limits across authentication, execution, and read endpoint categories with proper HTTP 429 responses and metrics integration.

## Workflow Type

**Type**: feature

**Rationale**: This is a new feature implementation adding production-critical security and stability infrastructure. While addressing technical debt, it introduces new functionality (rate limiting middleware, configuration, metrics) rather than refactoring existing code or fixing bugs. The implementation requires architectural decisions around storage backends, configuration patterns, and tiered limit strategies.

## Task Scope

### Services Involved
- **main** (primary) - Single FastAPI backend service requiring rate limiting protection

### This Task Will:
- [ ] Install and configure SlowAPI library for FastAPI integration
- [ ] Add rate limiting configuration to backend/core/config.py with environment variable support
- [ ] Initialize rate limiter in backend/main.py with global exception handler
- [ ] Apply tiered rate limits to authentication endpoints in backend/api/auth.py (10/minute)
- [ ] Apply execution rate limits to POST endpoints in backend/api/tools.py (5/minute)
- [ ] Apply read rate limits to GET endpoints in backend/api/tools.py (100/minute)
- [ ] Integrate rate limit metrics into existing /api/health endpoint
- [ ] Configure proper HTTP 429 responses with Retry-After headers
- [ ] Add optional Redis backend support for distributed deployments
- [ ] Document rate limits in OpenAPI/Swagger documentation
- [ ] Test rate limiting behavior and ensure graceful degradation

### Out of Scope:
- Per-user rate limiting (using IP-based limiting only)
- Custom rate limiting algorithms (using SlowAPI defaults)
- Rate limiting for frontend static assets
- Database connection pooling or other performance optimizations
- Rate limiting for workflow endpoints (sft_fixer, linux_qc_patching, etc.) - focused on core API routes only

## Service Context

### main

**Tech Stack:**
- Language: Python
- Framework: FastAPI
- Package Manager: poetry
- ORM: SQLAlchemy
- Key directories: tests/, backend/api/, backend/core/, backend/web/

**Entry Point:** `backend/main.py`

**How to Run:**
```bash
poetry install
poetry run uvicorn backend.main:app --reload --port 8500
```

**Port:** 8500

**Existing Middleware:**
- SessionMiddleware
- CORSMiddleware
- SecurityHeadersMiddleware
- CSRFProtectionMiddleware

**Health Endpoints:**
- `/health`
- `/api/health`
- `/feature-flags/health`

## Files to Modify

| File | Service | What to Change |
|------|---------|---------------|
| `backend/main.py` | main | Initialize SlowAPI limiter, add exception handler, integrate metrics into `/api/health` endpoint |
| `backend/core/config.py` | main | Add Pydantic Settings fields for rate limit configuration (RATE_LIMIT_AUTH_ENDPOINTS, RATE_LIMIT_EXECUTION_ENDPOINTS, RATE_LIMIT_READ_ENDPOINTS, REDIS_URL) |
| `backend/api/auth.py` | main | Apply `@limiter.limit()` decorators to authentication endpoints (POST /aws-credentials, GET /aws-credentials, etc.) |
| `backend/api/tools.py` | main | Apply execution limits to POST /{tool_id}/execute, read limits to GET / and GET /{tool_id} endpoints |
| `pyproject.toml` | main | Add slowapi>=0.1.9 dependency (optional: redis[hiredis]>=4.5.0 for production) |

## Files to Reference

These files show patterns to follow:

| File | Pattern to Copy |
|------|----------------|
| `backend/main.py` | Middleware initialization pattern, exception handler registration, health endpoint structure |
| `backend/core/config.py` | Pydantic Settings pattern for environment variable configuration |
| `backend/api/auth.py` | Existing router structure and endpoint patterns for authentication routes |
| `backend/api/tools.py` | Existing router structure for execution and read endpoints |

## Patterns to Follow

### Middleware Initialization Pattern

From `backend/main.py`:

```python
# Initialize middleware on FastAPI app
app.add_middleware(SessionMiddleware, secret_key="...")
app.add_middleware(CORSMiddleware, ...)

# Initialize limiter similarly
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

**Key Points:**
- Limiter must be attached to `app.state` before applying decorators
- Use `get_remote_address` for IP-based limiting (consider trusted proxy config if behind reverse proxy)
- Global exception handler provides consistent HTTP 429 responses

### Configuration Pattern

From `backend/core/config.py`:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Add rate limit configurations
    rate_limit_auth_endpoints: str = "10/minute"
    rate_limit_execution_endpoints: str = "5/minute"
    rate_limit_read_endpoints: str = "100/minute"
    redis_url: Optional[str] = None  # For distributed deployments

    class Config:
        env_file = ".env"
        case_sensitive = False
```

**Key Points:**
- Use Pydantic Settings for type-safe configuration
- Provide sensible defaults for development
- Support .env file for local overrides

### Route Decorator Pattern

Apply to endpoints in routers:

```python
from fastapi import Request

@router.post("/aws-credentials")
@limiter.limit(settings.rate_limit_auth_endpoints)
async def store_credentials(request: Request, ...):
    # Request parameter required for SlowAPI
    ...
```

**Key Points:**
- `Request` parameter must be included in function signature
- Limits can reference configuration values
- Decorator should be below route decorator

## Requirements

### Functional Requirements

1. **Configurable Rate Limits**
   - Description: Rate limits must be configurable via environment variables without code changes
   - Acceptance: Can modify `.env` file to change limits and restart service to apply changes

2. **HTTP 429 Responses**
   - Description: When rate limit exceeded, return HTTP 429 status with `Retry-After` header
   - Acceptance: curl request exceeding limit returns 429 with header indicating seconds to wait

3. **Tiered Endpoint Limits**
   - Description: Different rate limits for auth (10/min), execution (5/min), and read (100/min) endpoints
   - Acceptance: Auth endpoints hit limit at 10/min, execution at 5/min, read at 100/min

4. **Metrics Integration**
   - Description: Expose rate limiting status in existing `/api/health` endpoint
   - Acceptance: Health endpoint returns JSON with rate_limiting status and configuration

5. **Graceful Degradation**
   - Description: Rate limiting errors must not crash the application
   - Acceptance: Exceeding limits returns 429 but application continues serving other requests normally

### Edge Cases

1. **Redis Connection Failure** - If Redis backend configured but unavailable, fall back to in-memory limiting with warning log (don't crash)
2. **Malformed Rate Limit Strings** - If config contains invalid format (e.g., "abc/minute"), use default limit and log warning
3. **Missing Request Parameter** - If endpoint decorated but missing Request in signature, raise startup error (fail fast)
4. **Behind Reverse Proxy** - `get_remote_address()` may return proxy IP; consider configuring trusted proxies if X-Forwarded-For needed
5. **Concurrent Requests** - In-memory backend may have race conditions under high concurrency; Redis backend recommended for production

## Implementation Notes

### DO
- Follow the pattern in `backend/main.py` for middleware initialization
- Reuse existing Pydantic Settings pattern in `backend/core/config.py`
- Add `Request` parameter to all rate-limited endpoint signatures
- Test rate limiting with multiple rapid requests using curl or pytest
- Add rate limit info to OpenAPI schema using SlowAPI's documentation features
- Log rate limit violations for monitoring and debugging
- Use in-memory storage for development, Redis for production multi-instance deployments

### DON'T
- Create new configuration management system when Pydantic Settings exists
- Apply rate limits to static file serving or health check endpoints
- Use hard-coded rate limit values; always reference configuration
- Forget to add limiter to app.state before applying decorators (causes runtime errors)
- Use `slowapi.limit()` without Request parameter (will raise exceptions)
- Apply overly restrictive limits in development that hinder testing

## Development Environment

### Start Services

```bash
# Install dependencies
poetry install

# Run development server
poetry run uvicorn backend.main:app --reload --port 8500

# Optional: Start Redis for testing distributed rate limiting
docker run -d -p 6379:6379 redis:7-alpine
```

### Service URLs
- Main API: http://localhost:8500
- API Documentation: http://localhost:8500/docs
- Health Check: http://localhost:8500/api/health

### Required Environment Variables

Add to `.env` file:

```bash
# Rate Limiting Configuration
RATE_LIMIT_AUTH_ENDPOINTS="10/minute"
RATE_LIMIT_EXECUTION_ENDPOINTS="5/minute"
RATE_LIMIT_READ_ENDPOINTS="100/minute"

# Optional: Redis for distributed rate limiting
# REDIS_URL="redis://localhost:6379"
```

## Success Criteria

The task is complete when:

1. [ ] SlowAPI dependency installed and limiter initialized in backend/main.py
2. [ ] Rate limit configuration added to backend/core/config.py with environment variable support
3. [ ] Authentication endpoints rate limited at 10/minute
4. [ ] Execution endpoints rate limited at 5/minute
5. [ ] Read endpoints rate limited at 100/minute
6. [ ] HTTP 429 responses with Retry-After headers returned when limits exceeded
7. [ ] Rate limit metrics exposed in /api/health endpoint
8. [ ] No console errors or application crashes when limits exceeded
9. [ ] Existing tests still pass
10. [ ] Rate limiting behavior verified via manual testing (curl or browser)
11. [ ] OpenAPI documentation updated to show rate limits

## QA Acceptance Criteria

**CRITICAL**: These criteria must be verified by the QA Agent before sign-off.

### Unit Tests
| Test | File | What to Verify |
|------|------|----------------|
| test_rate_limit_config | `tests/test_config.py` | Configuration loads rate limit settings from environment variables correctly |
| test_limiter_initialization | `tests/test_main.py` | Limiter attached to app.state and exception handler registered |

### Integration Tests
| Test | Services | What to Verify |
|------|----------|----------------|
| test_auth_endpoint_rate_limit | main | POST /aws-credentials returns 429 after 10 requests in 1 minute |
| test_execution_endpoint_rate_limit | main | POST /api/tools/{tool_id}/execute returns 429 after 5 requests in 1 minute |
| test_read_endpoint_rate_limit | main | GET /api/tools returns 429 after 100 requests in 1 minute |
| test_retry_after_header | main | 429 response includes Retry-After header with seconds value |
| test_different_ips_independent_limits | main | Requests from different IPs have independent rate limit counters |

### End-to-End Tests
| Flow | Steps | Expected Outcome |
|------|-------|------------------|
| Rate Limit Exceeded Flow | 1. Send 11 requests to /aws-credentials within 1 minute 2. Check response status | First 10 return 200/201, 11th returns 429 with Retry-After header |
| Rate Limit Reset Flow | 1. Exceed rate limit 2. Wait duration from Retry-After header 3. Send new request | New request succeeds with 200 status |
| Health Metrics Flow | 1. GET /api/health 2. Check response JSON | Response includes rate_limiting status with configuration values |

### Browser Verification (if frontend)
| Page/Component | URL | Checks |
|----------------|-----|--------|
| API Documentation | `http://localhost:8500/docs` | Rate limit information visible in endpoint descriptions |
| Health Endpoint | `http://localhost:8500/api/health` | Returns JSON with rate_limiting metrics |

### Manual Testing Checklist
| Check | Command | Expected |
|-------|---------|----------|
| Auth rate limit | `for i in {1..11}; do curl -X POST http://localhost:8500/aws-credentials; done` | 11th request returns HTTP 429 |
| Retry-After header | `curl -i -X POST http://localhost:8500/aws-credentials` (after limit hit) | Response includes `Retry-After: <seconds>` header |
| Config changes apply | 1. Change RATE_LIMIT_AUTH_ENDPOINTS in .env 2. Restart server 3. Test limit | New limit applies without code changes |
| Redis backend (optional) | 1. Set REDIS_URL in .env 2. Start Redis 3. Test rate limiting | Limits work with Redis storage |
| Redis failure graceful | 1. Set REDIS_URL to invalid host 2. Start server | Server starts with in-memory fallback, logs warning |

### QA Sign-off Requirements
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] All E2E tests pass
- [ ] Manual testing checklist complete
- [ ] HTTP 429 responses properly formatted with Retry-After headers
- [ ] Rate limit metrics visible in health endpoint
- [ ] No regressions in existing functionality
- [ ] Configuration changes apply without code modification
- [ ] Code follows established patterns (Pydantic Settings, FastAPI middleware)
- [ ] No security vulnerabilities introduced (e.g., rate limit bypass)
- [ ] OpenAPI documentation updated
- [ ] Graceful degradation verified (Redis failure doesn't crash app)

## Implementation Strategy

### Phase 1: Foundation Setup
1. Add SlowAPI dependency to pyproject.toml
2. Add rate limit configuration to backend/core/config.py
3. Initialize limiter in backend/main.py with exception handler

### Phase 2: Apply Rate Limits
1. Apply auth limits to backend/api/auth.py endpoints
2. Apply execution limits to POST endpoints in backend/api/tools.py
3. Apply read limits to GET endpoints in backend/api/tools.py

### Phase 3: Observability
1. Add rate limit metrics to /api/health endpoint
2. Update OpenAPI documentation with rate limit information
3. Add logging for rate limit violations

### Phase 4: Testing & Validation
1. Write unit tests for configuration loading
2. Write integration tests for each rate limit tier
3. Perform manual testing with curl
4. Verify 429 responses and Retry-After headers
5. Test graceful degradation scenarios

### Phase 5: Optional Production Hardening
1. Add Redis backend support for distributed deployments
2. Configure trusted proxies if behind reverse proxy
3. Add monitoring/alerting for rate limit violations

## Risk Assessment

### High Risk
- **Proxy Configuration**: Default `get_remote_address()` may not work correctly behind reverse proxy; could rate limit all users as single IP
  - *Mitigation*: Test in production-like environment, configure trusted proxies if needed

- **Storage Backend**: In-memory storage doesn't work for multi-instance deployments; limits won't be shared
  - *Mitigation*: Document Redis requirement for production, provide configuration example

### Medium Risk
- **Overly Restrictive Limits**: Too-strict defaults could impact legitimate users
  - *Mitigation*: Use conservative defaults, make easily configurable, monitor violations

- **Testing Interference**: Rate limiting may break existing tests that make multiple rapid requests
  - *Mitigation*: Exempt test client from rate limiting or use high limits in test environment

### Low Risk
- **Performance Overhead**: Rate limiting adds per-request overhead
  - *Mitigation*: SlowAPI is lightweight, overhead negligible compared to typical API operations

## Security Considerations

1. **DoS Protection**: Primary goal is preventing DoS attacks; verify limits are low enough to prevent resource exhaustion
2. **IP Spoofing**: If behind proxy, ensure proper X-Forwarded-For handling to prevent IP spoofing bypasses
3. **Configuration Exposure**: Don't expose rate limit details to unauthenticated users (could help attackers optimize attacks)
4. **Redis Security**: If using Redis backend, ensure Redis instance is not publicly accessible

## Rollback Plan

If rate limiting causes production issues:

1. **Immediate**: Set all rate limit env vars to very high values (e.g., "10000/minute") and restart
2. **Short-term**: Comment out `@limiter.limit()` decorators and redeploy
3. **Full rollback**: Revert commit and redeploy previous version

All rollback options require service restart but no database migrations or state cleanup.
