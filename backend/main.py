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


def _check_storage_health() -> dict:
    """
    Check the health of the rate limiting storage backend.

    Returns dict with storage health status and details.
    """
    storage_type = "redis" if settings.redis_url else "memory"

    if storage_type == "memory":
        return {
            "type": "memory",
            "healthy": True,
            "message": "In-memory storage active",
        }

    # Check Redis connectivity if configured
    try:
        import redis

        # Parse Redis URL and test connection
        client = redis.from_url(settings.redis_url, socket_timeout=2)
        client.ping()
        return {
            "type": "redis",
            "healthy": True,
            "message": "Redis connection successful",
        }
    except ImportError:
        return {
            "type": "redis",
            "healthy": False,
            "message": "Redis client not installed",
        }
    except Exception as e:
        logger.warning("Redis health check failed: %s", str(e))
        return {
            "type": "redis",
            "healthy": False,
            "message": f"Redis connection failed: {str(e)}",
        }


@app.get("/api/health")
def api_health_check():
    """
    Enhanced health check endpoint with rate limiting status and metrics.

    Returns system health including rate limiting configuration, storage
    backend health, and protected endpoint information.
    """
    from datetime import datetime

    # Check storage backend health
    storage_health = _check_storage_health()

    # Determine overall rate limiting status
    rate_limit_enabled = hasattr(app.state, "limiter") and app.state.limiter is not None
    rate_limit_status = "enabled" if rate_limit_enabled else "disabled"

    # If storage is unhealthy but limiter is configured, report degraded status
    if rate_limit_enabled and not storage_health["healthy"]:
        rate_limit_status = "degraded"

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.0.0",
        "services": {
            "rate_limiting": {
                "status": rate_limit_status,
                "storage": storage_health,
                "configuration": {
                    "auth_endpoints": settings.rate_limit_auth_endpoints,
                    "execution_endpoints": settings.rate_limit_execution_endpoints,
                    "read_endpoints": settings.rate_limit_read_endpoints,
                },
                "endpoints_protected": {
                    "auth": [
                        "/api/auth/aws-credentials",
                    ],
                    "execution": [
                        "/api/tools/{tool_id}/execute",
                    ],
                    "read": [
                        "/api/tools/",
                        "/api/tools/{tool_id}",
                    ],
                },
            }
        },
    }
