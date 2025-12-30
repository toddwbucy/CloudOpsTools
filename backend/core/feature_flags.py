"""
Feature flag system for safe deployment of fixes and new features.

This module provides a centralized way to control feature rollouts and enable
safe rollbacks if issues are detected during deployment.
"""

import logging
import os
from enum import Enum
from typing import Dict, Any, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class FeatureFlagStatus(str, Enum):
    """Feature flag status options"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    GRADUAL_ROLLOUT = "gradual_rollout"  # For percentage-based rollouts
    DEV_ONLY = "dev_only"  # Only enabled in development


class FeatureFlag(BaseModel):
    """Individual feature flag configuration"""
    name: str
    status: FeatureFlagStatus
    description: str
    rollout_percentage: int = Field(default=0, ge=0, le=100)
    dev_override: bool = Field(default=False)
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "new_secret_key_handling",
                "status": "disabled", 
                "description": "Use environment variable for SECRET_KEY",
                "rollout_percentage": 0,
                "dev_override": False
            }
        }
    }


class FeatureFlagsConfig(BaseSettings):
    """Feature flags configuration from environment variables"""
    
    # Phase 1: Security Fixes
    NEW_SECRET_KEY_HANDLING: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    XSS_PROTECTION_ENABLED: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    CSRF_TOKENS_ENABLED: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    SECURE_CREDENTIAL_STORAGE: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    STRUCTURED_LOGGING: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    
    # Phase 2: Medium Risk Fixes
    THREAD_SAFE_SESSIONS: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    ATOMIC_SESSION_UPDATES: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    ENHANCED_ERROR_HANDLING: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    JS_MEMORY_LEAK_FIXES: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    PYDANTIC_V2_SCHEMAS: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    
    # Phase 3: Configuration & Infrastructure
    POSTGRESQL_SUPPORT: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    PRODUCTION_UVICORN_CONFIG: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    CREDENTIAL_HELPER_FUNCTIONS: FeatureFlagStatus = FeatureFlagStatus.DISABLED
    
    # Development and Testing
    DEBUG_MODE_ENABLED: bool = Field(default=False)
    STAGING_MODE_ENABLED: bool = Field(default=False)
    ROLLBACK_MODE_ENABLED: bool = Field(default=False)
    
    model_config = SettingsConfigDict(
        env_prefix="FEATURE_FLAG_",
        env_file=".env",
        case_sensitive=True
    )


class FeatureFlagManager:
    """Centralized feature flag management"""
    
    def __init__(self):
        self.config = FeatureFlagsConfig()
        self._cached_flags: Dict[str, bool] = {}
        logger.info("Feature flag manager initialized")
    
    def is_enabled(self, flag_name: str, user_id: Optional[str] = None) -> bool:
        """
        Check if a feature flag is enabled for the current context.
        
        Args:
            flag_name: Name of the feature flag
            user_id: Optional user ID for gradual rollouts
            
        Returns:
            True if feature is enabled, False otherwise
        """
        try:
            # Get the flag status from config
            flag_status = getattr(self.config, flag_name.upper(), FeatureFlagStatus.DISABLED)
            
            # Handle different flag statuses
            if flag_status == FeatureFlagStatus.ENABLED:
                return True
            elif flag_status == FeatureFlagStatus.DISABLED:
                return False
            elif flag_status == FeatureFlagStatus.DEV_ONLY:
                return self.config.DEBUG_MODE_ENABLED or self.config.STAGING_MODE_ENABLED
            elif flag_status == FeatureFlagStatus.GRADUAL_ROLLOUT:
                # Implement gradual rollout logic (placeholder)
                # In production, this could use user_id hash % 100
                return False
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking feature flag {flag_name}: {e}")
            return False
    
    def enable_flag(self, flag_name: str) -> bool:
        """
        Enable a feature flag (for testing/admin purposes).
        
        Args:
            flag_name: Name of the feature flag to enable
            
        Returns:
            True if successfully enabled, False otherwise
        """
        try:
            flag_attr = flag_name.upper()
            if hasattr(self.config, flag_attr):
                setattr(self.config, flag_attr, FeatureFlagStatus.ENABLED)
                logger.info(f"Feature flag {flag_name} enabled")
                return True
            else:
                logger.warning(f"Unknown feature flag: {flag_name}")
                return False
        except Exception as e:
            logger.error(f"Error enabling feature flag {flag_name}: {e}")
            return False
    
    def disable_flag(self, flag_name: str) -> bool:
        """
        Disable a feature flag (for rollback purposes).
        
        Args:
            flag_name: Name of the feature flag to disable
            
        Returns:
            True if successfully disabled, False otherwise
        """
        try:
            flag_attr = flag_name.upper()
            if hasattr(self.config, flag_attr):
                setattr(self.config, flag_attr, FeatureFlagStatus.DISABLED)
                logger.warning(f"Feature flag {flag_name} disabled (rollback?)")
                return True
            else:
                logger.warning(f"Unknown feature flag: {flag_name}")
                return False
        except Exception as e:
            logger.error(f"Error disabling feature flag {flag_name}: {e}")
            return False
    
    def get_all_flags(self) -> Dict[str, Any]:
        """
        Get all feature flags and their current status.
        
        Returns:
            Dictionary of all feature flags and their status
        """
        flags = {}
        for attr_name in dir(self.config):
            if not attr_name.startswith('_') and attr_name.isupper():
                flags[attr_name.lower()] = getattr(self.config, attr_name)
        return flags
    
    def health_check(self) -> Dict[str, Any]:
        """
        Feature flag system health check.
        
        Returns:
            Dictionary with system status and flag counts
        """
        all_flags = self.get_all_flags()
        enabled_count = sum(1 for flag in all_flags.values() 
                          if flag == FeatureFlagStatus.ENABLED or flag is True)
        
        return {
            "status": "healthy",
            "total_flags": len(all_flags),
            "enabled_flags": enabled_count,
            "rollback_mode": self.config.ROLLBACK_MODE_ENABLED,
            "debug_mode": self.config.DEBUG_MODE_ENABLED,
            "staging_mode": self.config.STAGING_MODE_ENABLED
        }


# Global feature flag manager instance
feature_flags = FeatureFlagManager()


# Convenience functions for common usage
def is_feature_enabled(flag_name: str, user_id: Optional[str] = None) -> bool:
    """Check if a feature flag is enabled"""
    return feature_flags.is_enabled(flag_name, user_id)


def enable_feature(flag_name: str) -> bool:
    """Enable a feature flag"""
    return feature_flags.enable_flag(flag_name)


def disable_feature(flag_name: str) -> bool:
    """Disable a feature flag"""
    return feature_flags.disable_flag(flag_name)


# Rollback helper
def emergency_rollback_all() -> None:
    """Emergency rollback - disable all feature flags"""
    logger.critical("EMERGENCY ROLLBACK: Disabling all feature flags")
    all_flags = feature_flags.get_all_flags()
    
    # Boolean development flags that should remain as booleans, not converted to FeatureFlagStatus
    boolean_dev_flags = ['debug_mode_enabled', 'staging_mode_enabled', 'rollback_mode_enabled']
    
    for flag_name in all_flags:
        if flag_name not in boolean_dev_flags:
            feature_flags.disable_flag(flag_name)