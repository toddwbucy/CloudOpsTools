"""CloudOpsTools Feature Flags Module"""

from dataclasses import dataclass
from typing import Dict, Optional


# Simple feature flag storage
_feature_flags = {}


def is_feature_enabled(feature_name: str) -> bool:
    """Check if a feature flag is enabled"""
    return _feature_flags.get(feature_name, False)


def set_feature_flag(feature_name: str, enabled: bool) -> None:
    """Set a feature flag"""
    _feature_flags[feature_name] = enabled


@dataclass
class FeatureFlagsConfig:
    """Configuration for feature flags"""
    DEBUG_MODE_ENABLED: bool = False
    STAGING_MODE_ENABLED: bool = False
    ROLLBACK_MODE_ENABLED: bool = False
    NEW_SECRET_KEY_HANDLING: str = "disabled"
    XSS_PROTECTION_ENABLED: str = "disabled"
    CSRF_TOKENS_ENABLED: str = "disabled"
    SECURE_CREDENTIAL_STORAGE: str = "disabled"
    STRUCTURED_LOGGING: str = "disabled"


class FeatureFlagManager:
    """Manager for feature flags"""

    def __init__(self, config: Optional[FeatureFlagsConfig] = None):
        self.config = config or FeatureFlagsConfig()
        self._flags: Dict[str, bool] = {}

    def is_enabled(self, flag_name: str) -> bool:
        """Check if a feature flag is enabled.

        First checks runtime overrides in self._flags, then falls back to
        config defaults. Handles both boolean and string ("enabled"/"disabled")
        config values.
        """
        # Check runtime overrides first
        if flag_name in self._flags:
            return self._flags[flag_name]

        # Fall back to config default if available
        if hasattr(self.config, flag_name):
            value = getattr(self.config, flag_name)
            # Handle both bool and string (\"enabled\"/\"disabled\") values
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() == "enabled"

        # Default to disabled if not found
        return False

    def enable_flag(self, flag_name: str) -> None:
        """Enable a feature flag"""
        self._flags[flag_name] = True

    def disable_flag(self, flag_name: str) -> None:
        """Disable a feature flag"""
        self._flags[flag_name] = False
