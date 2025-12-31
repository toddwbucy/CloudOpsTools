"""Authentication utilities for web workflows."""

from typing import Dict, Any
from fastapi import HTTPException, Request

from backend.core.config import settings
from backend.providers import get_provider
from backend.providers.base import ProviderBase
from backend.web.workflows.auth import get_session_credentials, get_session_provider


def get_authenticated_provider(request: Request) -> ProviderBase:
    """Get an authenticated provider instance from the session.

    Retrieves provider name and credentials from the current session
    and returns a configured provider instance.

    Args:
        request: FastAPI request object for session access.

    Returns:
        Configured provider instance.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if provider configuration is invalid.
    """
    provider_name = get_session_provider(request)
    credentials = get_session_credentials(request)

    if not provider_name or not credentials:
        # Fall back to default provider with config credentials
        provider_name = settings.DEFAULT_PROVIDER
        credentials = settings.get_provider_credentials(provider_name, "com")

        if not credentials or not credentials.get("access_key_id"):
            raise HTTPException(
                status_code=401,
                detail="Not authenticated. Please authenticate first via /auth/authenticate",
            )

    try:
        return get_provider(provider_name, credentials)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        ) from None
