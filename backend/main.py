"""
FastAPI application with rate limiting support.

This module initializes the main FastAPI application with SlowAPI rate limiting,
middleware, and route configuration.
"""

import logging

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.core.config import settings
from backend.core.limiter import limiter

# Initialize logging
logger = logging.getLogger(__name__)


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Unified platform for cloud operations management with rate limiting",
    version="2.0.0",
)

# Attach limiter to app.state for access in route decorators
# This must be done before applying @limiter.limit() decorators
app.state.limiter = limiter

# Add global exception handler for rate limit exceeded errors
# This ensures consistent HTTP 429 responses with Retry-After headers
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

logger.info(
    "Rate limiting initialized with configuration: auth=%s, execution=%s, read=%s",
    settings.rate_limit_auth_endpoints,
    settings.rate_limit_execution_endpoints,
    settings.rate_limit_read_endpoints,
)

# Import and register API routers
from backend.api.auth import router as auth_router
from backend.api.tools import router as tools_router

app.include_router(auth_router)
app.include_router(tools_router)


# Health check endpoint
@app.get("/health")
def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/health")
def api_health_check():
    """
    Enhanced health check endpoint with rate limiting status.

    Returns system health including rate limiting configuration and status.
    """
    from datetime import datetime

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.0.0",
        "services": {
            "rate_limiting": {
                "status": "enabled",
                "storage_backend": "redis" if settings.redis_url else "memory",
                "configuration": {
                    "auth_endpoints": settings.rate_limit_auth_endpoints,
                    "execution_endpoints": settings.rate_limit_execution_endpoints,
                    "read_endpoints": settings.rate_limit_read_endpoints,
                },
            }
        },
    }
