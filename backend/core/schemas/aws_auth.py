"""AWS Authentication Schemas"""

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict


class AWSAuthenticationRequest(BaseModel):
    """Schema for AWS authentication request with validation"""

    environment: Literal["com", "gov"] = Field(
        ..., description="AWS environment: 'com' for commercial or 'gov' for GovCloud"
    )
    access_key: str = Field(
        ..., min_length=16, max_length=128, description="AWS Access Key ID"
    )
    secret_key: str = Field(
        ..., min_length=40, max_length=128, description="AWS Secret Access Key"
    )
    session_token: Optional[str] = Field(
        None,
        min_length=100,
        description="AWS Session Token (required for temporary credentials)",
    )

    @field_validator("access_key")
    @classmethod
    def validate_access_key(cls, v: str) -> str:
        """Validate AWS Access Key format"""
        v = v.strip()
        if not v.startswith(("AKIA", "ASIA")):
            raise ValueError(
                "Invalid AWS Access Key format. Must start with 'AKIA' (permanent) or 'ASIA' (temporary)"
            )
        if len(v) != 20:
            raise ValueError("AWS Access Key must be exactly 20 characters long")
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate AWS Secret Key format"""
        v = v.strip()
        # AWS secret keys are 40 characters long and contain alphanumeric + / = characters
        if len(v) != 40:
            raise ValueError("AWS Secret Key must be exactly 40 characters long")
        # Basic character validation
        valid_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
        if not all(c in valid_chars for c in v):
            raise ValueError("AWS Secret Key contains invalid characters")
        return v

    @field_validator("session_token")
    @classmethod
    def validate_session_token(cls, v: Optional[str]) -> Optional[str]:
        """Validate AWS Session Token format"""
        if v is None:
            return v
        v = v.strip()
        # Session tokens are typically very long (100+ characters)
        if len(v) < 100:
            raise ValueError("AWS Session Token appears to be too short")
        return v

    @model_validator(mode="after")
    def check_temporary_credentials_consistency(self):
        """Validate that temporary credentials have a session token"""
        if self.access_key and self.access_key.startswith("ASIA"):
            # This is a temporary credential (starts with ASIA)
            if not self.session_token:
                raise ValueError(
                    "Session token is required for temporary AWS credentials (access key starts with 'ASIA')"
                )
        elif self.access_key and self.access_key.startswith("AKIA"):
            # This is a permanent credential (starts with AKIA)
            if self.session_token:
                # Warning: permanent credentials shouldn't have session tokens, but we'll allow it
                # as users might be using assumed role credentials
                pass
        return self

    model_config = ConfigDict(
        # Use enum values for serialization
        use_enum_values=True,
        # Example for documentation
        json_schema_extra={
            "example": {
                "environment": "com",
                "access_key": "ASIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "session_token": "IQoJb3JpZ2luX2VjEJr...very-long-token...",
            }
        }
    )


class AWSAuthenticationResponse(BaseModel):
    """Response schema for AWS authentication"""

    status: Literal["success", "error"] = Field(
        ..., description="Authentication status"
    )
    message: str = Field(
        ..., description="Human-readable message about the authentication result"
    )
    environment: Optional[str] = Field(
        None, description="The AWS environment that was authenticated"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "success",
                "message": "Successfully authenticated with COM environment",
                "environment": "com",
            }
        }
    )


class AWSCredentialTestResponse(BaseModel):
    """Response schema for credential testing"""

    status: Literal["success", "error"] = Field(..., description="Test status")
    message: str = Field(
        ..., description="Human-readable message about the test result"
    )
    details: Optional[dict] = Field(
        None, description="Additional details about the validation"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "success",
                "message": "Credentials are valid for COM environment",
                "details": {
                    "valid": True,
                    "message": "Credentials validated successfully",
                },
            }
        }
    )
