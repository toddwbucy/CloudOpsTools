"""AWS authentication web routes"""

from typing import Literal, cast

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError

from backend.core.config import AWSCredentials, AWSEnvironment
from backend.core.schemas.aws_auth import (
    AWSAuthenticationRequest,
    AWSAuthenticationResponse,
    AWSCredentialTestResponse,
)
from backend.core.templates import templates
from backend.providers.aws.common.services.credential_manager import CredentialManager

router = APIRouter()

# Create a shared credential manager instance
credential_manager = CredentialManager()


@router.get("/aws")
async def aws_auth_page(request: Request) -> HTMLResponse:
    """AWS authentication landing page"""
    # Check session for stored credentials
    session = request.session
    com_credentials = session.get("aws_com_credentials", False)
    gov_credentials = session.get("aws_gov_credentials", False)

    context = {
        "request": request,
        "com_credentials": com_credentials,
        "gov_credentials": gov_credentials,
    }

    return templates.TemplateResponse("aws/auth.html", context)


@router.get("/aws/tools")
async def aws_tools_page(request: Request) -> HTMLResponse:
    """AWS tools selection page"""
    # Check session for stored credentials
    session = request.session
    com_credentials = session.get("aws_com_credentials", False)
    gov_credentials = session.get("aws_gov_credentials", False)

    context = {
        "request": request,
        "com_credentials": com_credentials,
        "gov_credentials": gov_credentials,
    }

    return templates.TemplateResponse("aws/tools.html", context)


@router.post("/aws/authenticate", response_model=AWSAuthenticationResponse)
async def authenticate_aws(
    request: Request,
    environment: str = Form(...),
    access_key: str = Form(...),
    secret_key: str = Form(...),
    session_token: str = Form(None),
) -> AWSAuthenticationResponse:
    """Authenticate with AWS credentials using structured validation"""
    try:
        # Parse and validate form data using Pydantic model
        auth_request = AWSAuthenticationRequest(
            environment=cast(Literal["com", "gov"], environment),
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        )

        # Create credentials object with validated data
        aws_env = (
            AWSEnvironment.COM
            if auth_request.environment == "com"
            else AWSEnvironment.GOV
        )
        credentials = AWSCredentials(
            access_key=auth_request.access_key,
            secret_key=auth_request.secret_key,
            session_token=auth_request.session_token,
            environment=aws_env,
        )

        # Store credentials in shared credential manager
        credential_manager.store_credentials(credentials)

        # Validate credentials by making a test call
        validation_result = credential_manager.are_credentials_valid(aws_env.value)

        if not validation_result or not validation_result.get("valid", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid credentials for {auth_request.environment.upper()} environment",
            )

        # Store credential status in session
        session_key = f"aws_{auth_request.environment}_credentials"
        request.session[session_key] = True

        # Store encrypted credential data for recovery after server restart
        from backend.core.utils.encryption import encrypt_session_credentials

        session_creds_key = f"aws_{auth_request.environment}_credential_data"
        credential_data = {
            "access_key": auth_request.access_key,
            "secret_key": auth_request.secret_key,
            "session_token": auth_request.session_token
        }
        # Encrypt credentials before storing in session
        request.session[session_creds_key] = encrypt_session_credentials(credential_data)

        return AWSAuthenticationResponse(
            status="success",
            message=f"Successfully authenticated with {auth_request.environment.upper()} environment",
            environment=auth_request.environment,
        )

    except ValidationError as e:
        # Handle Pydantic validation errors
        error_messages = []
        for error in e.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            msg = error["msg"]
            error_messages.append(f"{field}: {msg}")

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Validation failed: " + "; ".join(error_messages),
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}",
        ) from e


@router.post("/aws/test-credentials", response_model=AWSCredentialTestResponse)
async def test_aws_credentials(
    request: Request,
    environment: str = Form(...),
    access_key: str = Form(...),
    secret_key: str = Form(...),
    session_token: str = Form(None),
) -> AWSCredentialTestResponse:
    """Test AWS credentials without storing them using structured validation"""
    try:
        # Parse and validate form data using Pydantic model
        auth_request = AWSAuthenticationRequest(
            environment=cast(Literal["com", "gov"], environment),
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        )

        # Use the validate_credentials method which doesn't store credentials
        is_valid, message = credential_manager.validate_credentials(
            access_key=auth_request.access_key,
            secret_key=auth_request.secret_key,
            session_token=auth_request.session_token,
            environment=auth_request.environment,
        )

        # Create validation result for compatibility
        validation_result = {"valid": is_valid, "message": message}

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid credentials for {auth_request.environment.upper()} environment: {message}",
            )

        return AWSCredentialTestResponse(
            status="success",
            message=f"Credentials are valid for {auth_request.environment.upper()} environment",
            details=validation_result,
        )

    except ValidationError as e:
        # Handle Pydantic validation errors
        error_messages = []
        for error in e.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            msg = error["msg"]
            error_messages.append(f"{field}: {msg}")

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Validation failed: " + "; ".join(error_messages),
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Credential test failed: {str(e)}",
        ) from e


@router.post("/aws/clear-credentials")
async def clear_aws_credentials(request: Request) -> JSONResponse:
    """Clear stored AWS credentials"""
    try:
        # Clear both environments
        credential_manager.clear_credentials("com")
        credential_manager.clear_credentials("gov")

        # Clear session
        request.session.pop("aws_com_credentials", None)
        request.session.pop("aws_gov_credentials", None)
        request.session.pop("aws_com_credential_data", None)
        request.session.pop("aws_gov_credential_data", None)

        return JSONResponse(
            content={"status": "success", "message": "All AWS credentials cleared"}
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear credentials: {str(e)}",
        ) from e


@router.get("/aws/status")
async def aws_credential_status(request: Request) -> JSONResponse:
    """Get current AWS credential status"""
    try:
        com_status = credential_manager.are_credentials_valid("com")
        gov_status = credential_manager.are_credentials_valid("gov")

        return JSONResponse(
            content={
                "com": {
                    "valid": com_status.get("valid", False) if com_status else False,
                    "details": com_status if com_status else {},
                },
                "gov": {
                    "valid": gov_status.get("valid", False) if gov_status else False,
                    "details": gov_status if gov_status else {},
                },
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get credential status: {str(e)}",
        ) from e
