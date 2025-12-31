"""
Authentication API endpoints with rate limiting.

This module provides authentication-related endpoints including AWS credential
management. All endpoints are rate limited to prevent abuse.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.core.limiter import limiter

# Create router for authentication endpoints
router = APIRouter(prefix="/api/auth", tags=["authentication"])


class AWSCredentials(BaseModel):
    """AWS credentials request/response model."""

    access_key: str = Field(..., description="AWS Access Key ID")
    secret_key: str = Field(..., description="AWS Secret Access Key")
    environment: str = Field(
        ..., description="AWS environment (e.g., 'com', 'gov')"
    )
    session_token: Optional[str] = Field(
        None, description="AWS Session Token (optional, for temporary credentials)"
    )


class CredentialResponse(BaseModel):
    """Response model for credential operations."""

    message: str
    environment: str


class CredentialStatus(BaseModel):
    """Response model for credential status check."""

    configured: bool
    environment: Optional[str] = None


# In-memory storage for demo purposes
# In production, this would use secure session storage or encrypted database
_credentials_store: dict = {}


@router.post("/aws-credentials", response_model=CredentialResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
async def store_credentials(request: Request, credentials: AWSCredentials):
    """
    Store AWS credentials for the current session.

    This endpoint is rate limited to prevent brute force attacks
    and credential stuffing attempts.

    Rate limit: 10 requests per minute per IP address.

    Args:
        request: FastAPI request object (required for rate limiting)
        credentials: AWS credentials to store

    Returns:
        CredentialResponse with success message

    Raises:
        HTTPException: If credentials are invalid
    """
    # Validate credentials format
    if not credentials.access_key or len(credentials.access_key) < 16:
        raise HTTPException(
            status_code=400,
            detail="Invalid access key format"
        )

    if not credentials.secret_key or len(credentials.secret_key) < 16:
        raise HTTPException(
            status_code=400,
            detail="Invalid secret key format"
        )

    if credentials.environment not in ("com", "gov"):
        raise HTTPException(
            status_code=400,
            detail="Environment must be 'com' or 'gov'"
        )

    # Store credentials (keyed by client IP for demo)
    client_ip = request.client.host if request.client else "unknown"
    _credentials_store[client_ip] = {
        "access_key": credentials.access_key,
        "secret_key": credentials.secret_key,
        "environment": credentials.environment,
        "session_token": credentials.session_token,
    }

    return CredentialResponse(
        message="AWS credentials stored successfully",
        environment=credentials.environment
    )


@router.get("/aws-credentials", response_model=CredentialStatus)
@limiter.limit(settings.rate_limit_auth_endpoints)
async def get_credentials_status(request: Request):
    """
    Check if AWS credentials are configured for the current session.

    This endpoint is rate limited to prevent enumeration attacks.

    Rate limit: 10 requests per minute per IP address.

    Args:
        request: FastAPI request object (required for rate limiting)

    Returns:
        CredentialStatus indicating if credentials are configured
    """
    client_ip = request.client.host if request.client else "unknown"
    creds = _credentials_store.get(client_ip)

    if creds:
        return CredentialStatus(
            configured=True,
            environment=creds.get("environment")
        )

    return CredentialStatus(configured=False)


@router.delete("/aws-credentials", response_model=CredentialResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
async def delete_credentials(request: Request):
    """
    Delete stored AWS credentials for the current session.

    This endpoint is rate limited to prevent abuse.

    Rate limit: 10 requests per minute per IP address.

    Args:
        request: FastAPI request object (required for rate limiting)

    Returns:
        CredentialResponse with success message

    Raises:
        HTTPException: If no credentials are stored
    """
    client_ip = request.client.host if request.client else "unknown"

    if client_ip not in _credentials_store:
        raise HTTPException(
            status_code=404,
            detail="No credentials found for this session"
        )

    del _credentials_store[client_ip]

    return CredentialResponse(
        message="AWS credentials deleted successfully",
        environment="none"
    )
