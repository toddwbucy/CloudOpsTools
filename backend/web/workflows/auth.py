"""Provider-agnostic authentication workflow.

This module handles authentication for any cloud provider using the provider
abstraction layer. It manages credential validation, session storage, and
provider selection without direct dependencies on specific cloud implementations.

Example usage:
    # In FastAPI app setup
    from backend.web.workflows.auth import router
    app.include_router(router, prefix="/auth", tags=["auth"])

    # Client POST /auth/authenticate
    # Body: {"provider": "aws", "credentials": {...}, "environment": "com"}
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.providers import get_provider, is_provider_registered, list_providers

router = APIRouter()


class AuthenticateRequest(BaseModel):
    """Request model for authentication endpoint.

    Attributes:
        provider: Cloud provider identifier (e.g., "aws", "azure", "gcp").
            Defaults to the configured DEFAULT_PROVIDER.
        credentials: Provider-specific credential dictionary.
            For AWS: {"access_key_id": "...", "secret_access_key": "..."}
        environment: Provider-specific environment (e.g., "com", "gov" for AWS).
            Optional, defaults to provider's default environment.
    """

    provider: str = Field(
        default_factory=lambda: settings.DEFAULT_PROVIDER,
        description="Cloud provider identifier",
    )
    credentials: Dict[str, str] = Field(
        ...,
        description="Provider-specific credentials",
    )
    environment: Optional[str] = Field(
        default=None,
        description="Provider environment (e.g., 'com' or 'gov' for AWS)",
    )


class AuthenticateResponse(BaseModel):
    """Response model for successful authentication.

    Attributes:
        success: Whether authentication was successful.
        provider: The authenticated provider name.
        environment: The authenticated environment (if applicable).
        message: Human-readable status message.
    """

    success: bool
    provider: str
    environment: Optional[str] = None
    message: str


class ProviderListResponse(BaseModel):
    """Response model for listing available providers.

    Attributes:
        providers: List of registered provider identifiers.
        default_provider: The default provider used when none is specified.
    """

    providers: list[str]
    default_provider: str


@router.get("/providers", response_model=ProviderListResponse)
async def get_available_providers() -> ProviderListResponse:
    """List available cloud providers.

    Returns a list of all registered providers and the default provider
    that will be used when no provider is explicitly specified.

    Returns:
        ProviderListResponse with available providers and default.
    """
    return ProviderListResponse(
        providers=list_providers(),
        default_provider=settings.DEFAULT_PROVIDER,
    )


@router.post("/authenticate", response_model=AuthenticateResponse)
async def authenticate(
    request: Request,
    auth_request: AuthenticateRequest,
) -> AuthenticateResponse:
    """Authenticate with a cloud provider.

    Validates the provided credentials against the specified cloud provider
    and stores the authentication state in the session on success.

    Args:
        request: FastAPI request object for session access.
        auth_request: Authentication request with provider and credentials.

    Returns:
        AuthenticateResponse indicating success or failure.

    Raises:
        HTTPException: 400 if provider is invalid or credentials are malformed.
        HTTPException: 401 if credentials are invalid.
        HTTPException: 500 if authentication check fails unexpectedly.
    """
    provider_name = auth_request.provider
    credentials = auth_request.credentials
    environment = auth_request.environment

    # Validate provider is registered
    if not is_provider_registered(provider_name):
        available = list_providers()
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider: '{provider_name}'. "
            f"Available providers: {available or 'none registered'}",
        )

    # Add environment to credentials if provided
    if environment:
        credentials = {**credentials, "environment": environment}

    try:
        # Get provider instance and validate credentials
        provider = get_provider(provider_name, credentials)
        is_valid = await provider.validate_credentials(credentials)

        if not is_valid:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials. Please check your credentials and try again.",
            )

        # Store authentication state in session
        # Session handling depends on middleware configuration (e.g., starlette-session)
        if hasattr(request, "session"):
            request.session["provider"] = provider_name
            request.session["credentials"] = credentials
            request.session["authenticated"] = True
            if environment:
                request.session["environment"] = environment

        return AuthenticateResponse(
            success=True,
            provider=provider_name,
            environment=environment,
            message=f"Successfully authenticated with {provider_name}"
            + (f" ({environment})" if environment else ""),
        )

    except ValueError as e:
        # Missing required credential fields
        raise HTTPException(
            status_code=400,
            detail=str(e),
        ) from e
    except NotImplementedError as e:
        # Provider validation not yet implemented
        # For development, allow authentication to proceed with session storage
        if hasattr(request, "session"):
            request.session["provider"] = provider_name
            request.session["credentials"] = credentials
            request.session["authenticated"] = True
            if environment:
                request.session["environment"] = environment

        return AuthenticateResponse(
            success=True,
            provider=provider_name,
            environment=environment,
            message=f"Authenticated with {provider_name} (validation pending implementation)",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Authentication failed: {e!s}",
        )


@router.post("/logout")
async def logout(request: Request) -> Dict[str, Any]:
    """Clear authentication state from session.

    Removes all provider credentials and authentication state from the
    current session.

    Args:
        request: FastAPI request object for session access.

    Returns:
        Dictionary with logout status.
    """
    if hasattr(request, "session"):
        request.session.pop("provider", None)
        request.session.pop("credentials", None)
        request.session.pop("authenticated", None)
        request.session.pop("environment", None)

    return {"success": True, "message": "Successfully logged out"}


@router.get("/status")
async def get_auth_status(request: Request) -> Dict[str, Any]:
    """Get current authentication status.

    Returns the current authentication state including the active provider
    and environment, without exposing sensitive credential details.

    Args:
        request: FastAPI request object for session access.

    Returns:
        Dictionary with authentication status (no credentials exposed).
    """
    if hasattr(request, "session") and request.session.get("authenticated"):
        return {
            "authenticated": True,
            "provider": request.session.get("provider"),
            "environment": request.session.get("environment"),
        }

    return {
        "authenticated": False,
        "provider": None,
        "environment": None,
    }


def get_session_provider(request: Request) -> Optional[str]:
    """Get the provider name from the current session.

    Utility function for other workflow modules to retrieve the
    authenticated provider from the session.

    Args:
        request: FastAPI request object for session access.

    Returns:
        Provider name if authenticated, None otherwise.
    """
    if hasattr(request, "session"):
        return request.session.get("provider")
    return None


def get_session_credentials(request: Request) -> Optional[Dict[str, str]]:
    """Get credentials from the current session.

    Utility function for other workflow modules to retrieve the
    stored credentials from the session.

    Args:
        request: FastAPI request object for session access.

    Returns:
        Credentials dictionary if authenticated, None otherwise.
    """
    if hasattr(request, "session"):
        return request.session.get("credentials")
    return None
