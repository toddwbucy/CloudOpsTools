from enum import Enum
from pathlib import Path
from typing import List, Optional
import logging

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AWSEnvironment(str, Enum):
    """AWS Environment types"""

    COM = "com"
    GOV = "gov"


class AWSCredentials(BaseSettings):
    """Settings model for AWS credentials"""

    access_key: str
    secret_key: str
    session_token: Optional[str] = None  # Optional for non-STS credentials
    expiration: Optional[int] = None
    environment: AWSEnvironment
    assumed_role: Optional[str] = None  # ARN of assumed role if using STS
    access_time: Optional[float] = None  # Track when credentials were stored

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, v):
        """Convert string environment to enum if needed"""
        if isinstance(v, str):
            return AWSEnvironment(v)
        return v

    @field_validator("expiration", mode="before")
    @classmethod
    def validate_expiration(cls, v):
        """Convert float expiration to int if needed"""
        if isinstance(v, float):
            return int(v)
        return v

    model_config = SettingsConfigDict(extra="allow")


class Settings(BaseSettings):
    """Application settings"""

    # Application settings
    APP_NAME: str = "PCM-Ops Tools"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    DEV_MODE: bool = False  # Set via environment variable, enables mock AWS operations

    # Security
    SECRET_KEY: str = "your-secret-key-here-change-in-production"

    # Database
    DATABASE_URL: str = "sqlite:///./data/pcm_ops_tools.db"
    SQLITE_DATABASE_URI: str = (
        "sqlite:///./data/pcm_ops_tools.db"  # Alias for compatibility
    )

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8500
    # CORS - Configure allowed origins via environment variable
    # Example: CORS_ORIGINS='["https://example.com", "https://app.example.com"]'
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:8500", "http://localhost:3000"],
        description="List of allowed CORS origins. Can be overridden via CORS_ORIGINS env var as JSON array"
    )

    # Frontend settings (now integrated)
    UPLOAD_FOLDER: Path = Path("./uploads")
    MAX_CONTENT_LENGTH: int = 10 * 1024 * 1024  # 10MB

    # AWS settings
    AWS_DEFAULT_REGION: str = "us-east-1"

    # AWS Credentials for COM environment
    AWS_ACCESS_KEY_ID_COM: Optional[str] = None
    AWS_SECRET_ACCESS_KEY_COM: Optional[str] = None
    AWS_SESSION_TOKEN_COM: Optional[str] = None

    # AWS Credentials for GOV environment
    AWS_ACCESS_KEY_ID_GOV: Optional[str] = None
    AWS_SECRET_ACCESS_KEY_GOV: Optional[str] = None
    AWS_SESSION_TOKEN_GOV: Optional[str] = None

    # Session settings
    SESSION_LIFETIME_MINUTES: int = 30

    # API settings (for any external integrations)
    API_TIMEOUT: int = 30

    # Script execution settings
    MAX_CONCURRENT_EXECUTIONS: int = 5
    EXECUTION_TIMEOUT: int = 1800  # 30 minutes

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS_ORIGINS from JSON string if provided as env var"""
        if isinstance(v, str):
            import json
            try:
                # Try to parse as JSON array
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
                else:
                    raise ValueError("CORS_ORIGINS must be a JSON array")
            except json.JSONDecodeError:
                # If not valid JSON, treat as comma-separated list
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure upload folder exists
        self.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        # Ensure data directory exists
        Path("./data").mkdir(parents=True, exist_ok=True)
        
        # Apply Phase 1 security fixes if feature flag is enabled
        self._apply_phase1_security_fixes()

    def get_credentials(self, environment: AWSEnvironment) -> Optional[AWSCredentials]:
        """Get credentials for a specific environment"""
        if environment == AWSEnvironment.COM:
            if not self.AWS_ACCESS_KEY_ID_COM or not self.AWS_SECRET_ACCESS_KEY_COM:
                return None

            return AWSCredentials(
                access_key=self.AWS_ACCESS_KEY_ID_COM,
                secret_key=self.AWS_SECRET_ACCESS_KEY_COM,
                session_token=self.AWS_SESSION_TOKEN_COM,
                environment=AWSEnvironment.COM,
            )

        elif environment == AWSEnvironment.GOV:
            if not self.AWS_ACCESS_KEY_ID_GOV or not self.AWS_SECRET_ACCESS_KEY_GOV:
                return None

            return AWSCredentials(
                access_key=self.AWS_ACCESS_KEY_ID_GOV,
                secret_key=self.AWS_SECRET_ACCESS_KEY_GOV,
                session_token=self.AWS_SESSION_TOKEN_GOV,
                environment=AWSEnvironment.GOV,
            )

        return None

    def get_available_environments(self) -> List[AWSEnvironment]:
        """Get list of environments with available credentials"""
        environments = []

        if self.AWS_ACCESS_KEY_ID_COM and self.AWS_SECRET_ACCESS_KEY_COM:
            environments.append(AWSEnvironment.COM)

        if self.AWS_ACCESS_KEY_ID_GOV and self.AWS_SECRET_ACCESS_KEY_GOV:
            environments.append(AWSEnvironment.GOV)

        return environments
    
    def _apply_phase1_security_fixes(self):
        """Apply Phase 1 security fixes when feature flags are enabled"""
        try:
            # Import here to avoid circular imports
            from backend.core.feature_flags import is_feature_enabled
            
            # Fix 1: Secure SECRET_KEY handling
            if is_feature_enabled('NEW_SECRET_KEY_HANDLING'):
                from backend.core.security import get_or_create_secret_key
                try:
                    secure_key = get_or_create_secret_key()
                    self.SECRET_KEY = secure_key
                    logging.getLogger(__name__).info("Applied secure SECRET_KEY handling")
                except Exception as e:
                    logging.getLogger(__name__).error(f"Failed to apply secure SECRET_KEY: {e}")
                    # Keep the existing key but warn
                    logging.getLogger(__name__).warning("Continuing with existing SECRET_KEY (security risk)")
        
        except ImportError:
            # Feature flags not available during early initialization
            pass


# Create settings instance
settings = Settings()
