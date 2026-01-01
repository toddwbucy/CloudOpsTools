import logging
import time
from typing import Dict, Optional, Tuple, Union

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from backend.core.config import settings
from backend.core.limiter import limiter
from backend.providers.aws.common.services.credential_manager import CredentialManager

logger = logging.getLogger(__name__)

# Create an instance of the credential manager
cm = CredentialManager()

# Environment-specific settings for direct validation
ENV_CONFIGS = {
    "gov": {
        "region": "us-gov-west-1",
        "endpoint": "https://sts.us-gov-west-1.amazonaws.com",
    },
    "com": {
        "region": "us-east-1",
        "endpoint": "https://sts.us-east-1.amazonaws.com",
    },
}

# Create router
router = APIRouter()


def _validate_credentials_only(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
    environment: str = "com",
) -> Tuple[bool, str]:
    """
    Validate AWS credentials without storing them.

    This is a simplified validation function that only checks if credentials
    are valid by making a test AWS API call. No caching or storage.
    """
    environment = environment.lower()
    logger.info(
        f"Validating credentials for {environment.upper()} environment (no storage)"
    )

    try:
        env_config = ENV_CONFIGS.get(environment)
        if not env_config:
            return False, f"Invalid environment: {environment}"

        logger.debug(f"Using endpoint: {env_config['endpoint']}")

        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )

        sts = session.client(
            "sts", region_name=env_config["region"], endpoint_url=env_config["endpoint"]
        )

        logger.debug("Attempting to get caller identity...")
        response = sts.get_caller_identity()

        account_id = response.get("Account", "Unknown")
        logger.info(
            f"Successfully validated {environment.upper()} credentials for account: {account_id}"
        )

        # Log security event for successful validation
        from backend.core.logging_config import log_credential_access
        log_credential_access('validation', environment, True)

        return (
            True,
            f"Successfully validated {environment} credentials for account: {account_id}",
        )

    except ClientError as e:
        # Log the full error internally for debugging
        logger.error(
            f"Failed to validate {environment.upper()} credentials: {str(e)}"
        )
        
        # Log security event
        from backend.core.logging_config import log_credential_access
        log_credential_access('validation', environment, False)
        
        # Return a sanitized error message for API responses
        from backend.core.security import create_safe_error_response
        safe_message = create_safe_error_response(e, "AWS credential validation failed")
        return False, safe_message

    except Exception as e:
        # Log the full error internally for debugging
        logger.error(
            f"Unexpected error validating {environment.upper()} credentials: {str(e)}"
        )
        
        # Log security event
        from backend.core.logging_config import log_credential_access
        log_credential_access('validation', environment, False)
        
        # Return a sanitized error message for API responses
        from backend.core.security import create_safe_error_response
        safe_message = create_safe_error_response(e, "Credential validation error")
        return False, safe_message


class CredentialRequest(BaseModel):
    """Request model for credential validation"""

    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    environment: str
    expiration: Optional[int] = None
    
    @field_validator('access_key')
    @classmethod
    def validate_access_key(cls, v):
        """Validate access key format and prevent injection attacks"""
        if not v or not isinstance(v, str):
            raise ValueError("Access key must be a non-empty string")
            
        # Remove any potential XSS/injection attempts
        from backend.core.security import sanitize_log_data
        sanitized = sanitize_log_data(v, max_length=50)
        
        # Basic AWS access key format validation
        if not v.strip():
            raise ValueError("Access key cannot be empty")
            
        # AWS access keys follow specific patterns - validate with comprehensive regex
        import re
        
        # AWS access key pattern: Known AWS prefixes + 16 alphanumeric characters
        # AKIA: Standard access keys, ASIA: STS temporary, AROA: Role, AIDA: IAM user, AIPA: Service roles
        aws_key_pattern = r'^(AKIA|ASIA|AROA|AIDA|AIPA)[A-Z0-9]{16}$'
        
        cleaned_key = v.replace(' ', '')
        if not re.match(aws_key_pattern, cleaned_key):
            raise ValueError("Invalid AWS access key format")
                
        return v.strip()
    
    @field_validator('secret_key')
    @classmethod  
    def validate_secret_key(cls, v):
        """Validate secret key and prevent injection attacks"""
        if not v or not isinstance(v, str):
            raise ValueError("Secret key must be a non-empty string")
            
        # Remove any potential XSS/injection attempts
        stripped = v.strip()
        if not stripped:
            raise ValueError("Secret key cannot be empty")
            
        # Check for obvious injection patterns
        dangerous_patterns = ['<script', 'javascript:', 'data:', 'vbscript:', '<iframe', 'onload=', 'onerror=']
        v_lower = v.lower()
        for pattern in dangerous_patterns:
            if pattern in v_lower:
                raise ValueError("Invalid characters in secret key")
                
        return stripped
    
    @field_validator('environment')
    @classmethod
    def validate_environment(cls, v):
        """Validate environment parameter"""
        if not v or not isinstance(v, str):
            raise ValueError("Environment must be specified")
            
        # Only allow specific valid environments
        valid_envs = ['com', 'gov', 'COM', 'GOV']
        if v not in valid_envs:
            raise ValueError("Environment must be 'com' or 'gov'")
            
        return v.lower()
    
    @field_validator('session_token')
    @classmethod
    def validate_session_token(cls, v):
        """Validate session token if provided"""
        if v is None:
            return v
            
        if not isinstance(v, str):
            raise ValueError("Session token must be a string")
            
        # Check for XSS patterns
        dangerous_patterns = ['<script', 'javascript:', 'data:', '<iframe', 'onload=', 'onerror=']
        v_lower = v.lower()
        for pattern in dangerous_patterns:
            if pattern in v_lower:
                raise ValueError("Invalid characters in session token")
                
        return v.strip()


class CredentialResponse(BaseModel):
    """Response model for credential operations"""

    success: bool
    message: str
    environment: str
    expiration: Optional[float] = None
    expires_in_seconds: Optional[int] = None
    expires_in_minutes: Optional[float] = None
    temporary: Optional[bool] = None


class CredentialStatusResponse(BaseModel):
    """Response model for credential status"""

    environment: str
    valid: bool
    message: str
    expiration: Optional[int] = None
    expires_in_seconds: Optional[int] = None
    expires_in_minutes: Optional[float] = None
    temporary: Optional[bool] = None


class CredentialEnvironmentsResponse(BaseModel):
    """Response model for listing credential environments"""

    environments: list[str]


class CredentialCheckResponse(BaseModel):
    """Response model for the detailed credential check endpoint"""

    class CredentialCheckItem(BaseModel):
        valid: bool
        expiring_soon: bool
        time_remaining: Optional[int] = None
        environment: str
        access_key: Optional[str] = None
        expiration: Optional[int] = None
        has_session_token: Optional[bool] = None

    com: Optional[CredentialCheckItem] = None
    gov: Optional[CredentialCheckItem] = None


@router.post("/aws-credentials", response_model=CredentialResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
def validate_aws_credentials(request: Request, req: CredentialRequest) -> CredentialResponse:
    """
    Validate AWS credentials without storing them.

    This endpoint validates AWS credentials for a specific environment (gov or com)
    but does NOT store them server-side. The frontend stores credentials
    in the session and sends them with each API request that needs them.
    
    This endpoint is rate limited to prevent abuse and brute force attacks.
    Rate limit: Configured via settings.rate_limit_auth_endpoints
    """
    # Use validation-only function instead of storing
    success, message = _validate_credentials_only(
        access_key=req.access_key,
        secret_key=req.secret_key,
        session_token=req.session_token,
        environment=req.environment,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    # Return validation result with expiration info for temporary credentials
    response = CredentialResponse(
        success=True,
        message=message,
        environment=req.environment,
        temporary=req.session_token is not None,
    )

    # For temporary credentials, calculate expiration (STS tokens typically last 45 min)
    if req.session_token is not None:
        # Default STS token duration is 45 minutes
        now = time.time()
        expiration_time = now + (45 * 60)  # 45 minutes from now
        seconds_remaining = 45 * 60
        response.expiration = expiration_time
        response.expires_in_seconds = int(seconds_remaining)
        response.expires_in_minutes = 45.0

    return response


@router.get("/aws-credentials/{environment}", response_model=CredentialStatusResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
def get_aws_credential_status(request: Request, environment: str) -> CredentialStatusResponse:
    """
    Get status of AWS credentials for a specific environment.

    This endpoint checks if valid credentials exist for the specified environment
    and returns their expiration time if available.
    
    This endpoint is rate limited to prevent enumeration attacks.
    Rate limit: Configured via settings.rate_limit_auth_endpoints
    """
    try:
        status_data = cm.are_credentials_valid(environment)  # type: ignore
        is_valid = status_data.get("valid", False)
        creds = cm.get_credentials(environment) if is_valid else None
    except Exception as e:
        logger.error(f"Error checking credential validity: {str(e)}")
        is_valid = False
        creds = None
        status_data = {"valid": False, "expiring_soon": False, "time_remaining": None}

    response = CredentialStatusResponse(
        environment=environment,
        valid=is_valid,
        message=f"Credentials for {environment} are {'valid' if is_valid else 'invalid or expired'}",
    )

    # Add expiration information if credentials exist
    if creds and creds.expiration is not None:
        now = time.time()
        seconds_remaining = max(0, creds.expiration - now)
        response.expiration = creds.expiration  # type: ignore
        response.expires_in_seconds = int(seconds_remaining)  # type: ignore
        response.expires_in_minutes = round(seconds_remaining / 60, 1)  # type: ignore
        response.temporary = creds.session_token is not None  # type: ignore

    return response


@router.delete(
    "/aws-credentials/{environment}", response_model=Dict[str, Union[str, bool]]
)
@limiter.limit(settings.rate_limit_auth_endpoints)
def clear_aws_credentials(request: Request, environment: str) -> Dict[str, Union[str, bool]]:
    """
    Clear AWS credentials for a specific environment.

    This endpoint removes stored credentials for the specified environment.
    
    This endpoint is rate limited to prevent abuse.
    Rate limit: Configured via settings.rate_limit_auth_endpoints
    """
    cm.clear_credentials(environment)

    return {
        "success": True,
        "message": f"Credentials for {environment} have been cleared",
    }


@router.get("/aws-credentials", response_model=CredentialEnvironmentsResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
def list_aws_credential_environments(request: Request) -> CredentialEnvironmentsResponse:
    """
    List all supported AWS credential environments.

    With client-side credential management, this endpoint returns the static
    list of supported environments. Actual credential validity is managed
    client-side.
    
    This endpoint is rate limited to prevent enumeration attacks.
    Rate limit: Configured via settings.rate_limit_auth_endpoints
    """
    # Return static list of supported environments
    supported_environments = ["com", "gov"]

    return CredentialEnvironmentsResponse(environments=supported_environments)


# The refresh endpoint has been removed as it's no longer needed.
# Credential validation now returns expiration information directly,
# allowing the frontend to manage credential lifecycles without a separate refresh endpoint.


@router.get("/aws-check-credentials", response_model=CredentialCheckResponse)
@limiter.limit(settings.rate_limit_auth_endpoints)
def check_aws_credentials(request: Request) -> CredentialCheckResponse:
    """
    Check status of backend-configured AWS credentials.

    This endpoint checks which environments have valid credentials configured
    through environment variables and returns their status.
    
    This endpoint is rate limited to prevent enumeration attacks.
    Rate limit: Configured via settings.rate_limit_auth_endpoints
    """
    result = CredentialCheckResponse()

    # Check both environments for backend-configured credentials
    for env in ["com", "gov"]:
        try:
            # Check if credentials are configured and valid
            status_data = cm.are_credentials_valid(env)
            is_valid = status_data.get("valid", False)
            creds = cm.get_credentials(env) if is_valid else None

            # Create status item
            status = CredentialCheckResponse.CredentialCheckItem(
                valid=is_valid,
                expiring_soon=status_data.get("expiring_soon", False),
                time_remaining=status_data.get("time_remaining"),
                environment=env,
                has_session_token=creds.session_token is not None if creds else False,
            )

            # Add expiration info if available
            if creds and creds.expiration is not None:
                status.expiration = int(creds.expiration)

            # Mask access key for security (show only first 4 and last 4 chars)
            if creds and creds.access_key:
                access_key = creds.access_key
                if len(access_key) > 8:
                    status.access_key = f"{access_key[:4]}...{access_key[-4:]}"
                else:
                    status.access_key = "****"

        except Exception as e:
            logger.error(f"Error checking {env} credentials: {str(e)}")
            # Return invalid status on error
            status = CredentialCheckResponse.CredentialCheckItem(
                valid=False, expiring_soon=False, time_remaining=None, environment=env
            )

        # Assign to result
        if env == "com":
            result.com = status
        elif env == "gov":
            result.gov = status

    return result