"""
Application configuration using Pydantic Settings.

Configuration values can be set via environment variables or .env file.
"""

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    app_name: str = "CloudOpsTools"
    debug: bool = False

    # Rate limiting configuration
    rate_limit_auth_endpoints: str = "10/minute"
    rate_limit_execution_endpoints: str = "5/minute"
    rate_limit_read_endpoints: str = "100/minute"

    # Optional Redis URL for distributed rate limiting
    # When set, rate limits will be shared across multiple instances
    redis_url: Optional[str] = None


# Global settings instance
settings = Settings()
