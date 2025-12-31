"""
FastAPI application with rate limiting support.

This module initializes the main FastAPI application with SlowAPI rate limiting,
middleware, and route configuration.
"""

import logging
from typing import Optional

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.core.config import settings

# Initialize logging
logger = logging.getLogger(__name__)


def get_limiter_storage() -> Optional[str]:
    """
    Get the storage backend for rate limiting.

    Returns Redis URL if configured, otherwise None (uses in-memory storage).
    Logs warnings for Redis configuration issues.
    """
    if settings.redis_url:
        try:
            # Validate Redis URL format
            if not settings.redis_url.startswith(("redis://", "rediss://")):
                logger.warning(
                    "Invalid REDIS_URL format: %s. Using in-memory storage instead.",
                    settings.redis_url
                )
                return None
            logger.info("Using Redis backend for rate limiting: %s", settings.redis_url)
            return settings.redis_url
        except Exception as e:
            logger.warning(
                "Failed to configure Redis storage for rate limiting: %s. "
                "Falling back to in-memory storage.",
                str(e)
            )
            return None
    return None


def create_limiter() -> Limiter:
    """
    Create and configure the SlowAPI rate limiter.

    Uses Redis backend if REDIS_URL is configured, otherwise falls back to
    in-memory storage. In-memory storage is suitable for single-instance
    deployments, while Redis is required for distributed deployments.

    Returns:
        Configured Limiter instance
    """
    storage_uri = get_limiter_storage()

    if storage_uri:
        return Limiter(
            key_func=get_remote_address,
            storage_uri=storage_uri,
            default_limits=[]  # No default limits - apply explicitly per endpoint
        )
    else:
        logger.info("Using in-memory storage for rate limiting")
        return Limiter(
            key_func=get_remote_address,
            default_limits=[]  # No default limits - apply explicitly per endpoint
        )


# Create the rate limiter instance
limiter = create_limiter()


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
