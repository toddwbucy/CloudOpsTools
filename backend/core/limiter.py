"""
Rate limiter configuration module.

This module creates the SlowAPI rate limiter instance that can be imported
by route modules without circular import issues.
"""

import logging
from typing import Optional

from slowapi import Limiter
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


# Create the rate limiter instance - this is the single instance used throughout the app
limiter = create_limiter()
