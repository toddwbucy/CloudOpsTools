"""Application configuration with multi-provider support.

This module provides centralized configuration management using Pydantic v2
settings. It supports multiple cloud providers with environment-specific
credentials while maintaining backward compatibility with existing AWS
environment variables.

Example usage:
    from backend.core.config import settings

    # Get default provider
    provider_name = settings.DEFAULT_PROVIDER

    # Get credentials for a specific provider and environment
    aws_creds = settings.get_provider_credentials("aws", "com")
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with multi-provider credential support.

    Environment variables are loaded from .env file if present.
    AWS credentials maintain backward compatibility with existing
    _COM and _GOV suffixes for Commercial and GovCloud environments.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore extra env vars not defined in the model
    )

    # Application settings
    APP_NAME: str = "CloudOpsTools"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    DEV_MODE: bool = False  # Set via environment variable, enables mock AWS operations

    # Security
    SECRET_KEY: str = "your-secret-key-here-change-in-production"

    # Database
    DATABASE_URL: str = "sqlite:///./data/cloudopstools.db"
    SQLITE_DATABASE_URI: str = (
        "sqlite:///./data/cloudopstools.db"  # Alias for compatibility
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

    # AWS Commercial environment credentials (backward compatible)
    AWS_ACCESS_KEY_ID_COM: Optional[str] = None
    AWS_SECRET_ACCESS_KEY_COM: Optional[str] = None

    # AWS GovCloud environment credentials (backward compatible)
    AWS_ACCESS_KEY_ID_GOV: Optional[str] = None
    AWS_SECRET_ACCESS_KEY_GOV: Optional[str] = None
    AWS_SESSION_TOKEN_COM: Optional[str] = None
    AWS_SESSION_TOKEN_GOV: Optional[str] = None

    # Session settings
    SESSION_LIFETIME_MINUTES: int = 30

    # API settings (for any external integrations)
    API_TIMEOUT: int = 30

    # Script execution settings
    MAX_CONCURRENT_EXECUTIONS: int = 5
    EXECUTION_TIMEOUT: int = 1800  # 30 minutes

    # Default provider when not specified in session
    DEFAULT_PROVIDER: str = "aws"

    def get_provider_credentials(
        self, provider: str, environment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get credentials for a specific provider and environment.

        Args:
            provider: Provider identifier (e.g., "aws", "azure", "gcp").
            environment: Provider-specific environment (e.g., "com", "gov" for AWS).
                If None, returns all environments for the provider.

        Returns:
            Dictionary with credentials for the specified provider/environment.
            For AWS with environment specified:
                {"access_key_id": "...", "secret_access_key": "..."}
            For AWS without environment (all environments):
                {
                    "com": {"access_key_id": "...", "secret_access_key": "..."},
                    "gov": {"access_key_id": "...", "secret_access_key": "..."}
                }

        Raises:
            ValueError: If provider is not supported or environment is invalid.
        """
        provider_creds = self._get_all_provider_credentials()

        if provider not in provider_creds:
            available = list(provider_creds.keys())
            raise ValueError(
                f"Unknown provider: '{provider}'. "
                f"Available providers: {available or 'none configured'}"
            )

        if environment is None:
            return provider_creds[provider]

        env_creds = provider_creds[provider]
        if environment not in env_creds:
            available = list(env_creds.keys())
            raise ValueError(
                f"Unknown environment '{environment}' for provider '{provider}'. "
                f"Available environments: {available or 'none configured'}"
            )

        return env_creds[environment]

    def _get_all_provider_credentials(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Return credentials organized by provider and environment.

        Returns:
            Nested dictionary structure:
            {
                "aws": {
                    "com": {"access_key_id": "...", "secret_access_key": "..."},
                    "gov": {"access_key_id": "...", "secret_access_key": "..."}
                },
                # Future: "azure": {...}, "gcp": {...}
            }
        """
        return {
            "aws": {
                "com": {
                    "access_key_id": self.AWS_ACCESS_KEY_ID_COM,
                    "secret_access_key": self.AWS_SECRET_ACCESS_KEY_COM,
                },
                "gov": {
                    "access_key_id": self.AWS_ACCESS_KEY_ID_GOV,
                    "secret_access_key": self.AWS_SECRET_ACCESS_KEY_GOV,
                },
            },
            # Future: "azure": {...}, "gcp": {...}
        }


# Global settings instance
settings = Settings()
