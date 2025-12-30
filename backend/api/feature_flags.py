"""
Feature flag management API endpoints.

These endpoints allow runtime control of feature flags for safe deployment
and rollback capabilities.
"""

import logging
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.core.feature_flags import feature_flags, FeatureFlagStatus

logger = logging.getLogger(__name__)

router = APIRouter()


class FeatureFlagToggle(BaseModel):
    """Request model for toggling feature flags"""
    flag_name: str
    enabled: bool
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "flag_name": "new_secret_key_handling",
                "enabled": True
            }
        }
    }


class FeatureFlagStatus(BaseModel):
    """Response model for feature flag status"""
    flag_name: str
    enabled: bool
    status: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "flag_name": "new_secret_key_handling",
                "enabled": False,
                "status": "disabled"
            }
        }
    }


class FeatureFlagsHealthResponse(BaseModel):
    """Response model for feature flags health check"""
    status: str
    total_flags: int
    enabled_flags: int
    rollback_mode: bool
    debug_mode: bool
    staging_mode: bool
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "healthy",
                "total_flags": 12,
                "enabled_flags": 2,
                "rollback_mode": False,
                "debug_mode": True,
                "staging_mode": False
            }
        }
    }


@router.get("/feature-flags/health", response_model=FeatureFlagsHealthResponse)
def get_feature_flags_health() -> FeatureFlagsHealthResponse:
    """
    Get feature flag system health status.
    
    Returns overall system health and flag statistics.
    """
    try:
        health_data = feature_flags.health_check()
        return FeatureFlagsHealthResponse(**health_data)
    except Exception as e:
        logger.error(f"Error checking feature flags health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error checking feature flags health"
        )


@router.get("/feature-flags", response_model=Dict[str, Any])
def list_all_feature_flags() -> Dict[str, Any]:
    """
    List all feature flags and their current status.
    
    Returns dictionary of all feature flags with their status.
    """
    try:
        return feature_flags.get_all_flags()
    except Exception as e:
        logger.error(f"Error listing feature flags: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error listing feature flags"
        )


@router.get("/feature-flags/{flag_name}", response_model=FeatureFlagStatus)
def get_feature_flag_status(flag_name: str) -> FeatureFlagStatus:
    """
    Get the status of a specific feature flag.
    
    Args:
        flag_name: Name of the feature flag
        
    Returns:
        Current status of the feature flag
    """
    try:
        enabled = feature_flags.is_enabled(flag_name)
        all_flags = feature_flags.get_all_flags()
        flag_status = all_flags.get(flag_name.lower(), "unknown")
        
        return FeatureFlagStatus(
            flag_name=flag_name,
            enabled=enabled,
            status=str(flag_status)
        )
    except Exception as e:
        logger.error(f"Error getting feature flag {flag_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting feature flag {flag_name}"
        )


@router.post("/feature-flags/toggle", response_model=FeatureFlagStatus)
def toggle_feature_flag(request: FeatureFlagToggle) -> FeatureFlagStatus:
    """
    Toggle a feature flag on or off.
    
    Args:
        request: Feature flag toggle request
        
    Returns:
        Updated status of the feature flag
    """
    try:
        flag_name = request.flag_name
        
        if request.enabled:
            success = feature_flags.enable_flag(flag_name)
            action = "enabled"
        else:
            success = feature_flags.disable_flag(flag_name)
            action = "disabled"
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to toggle feature flag {flag_name}"
            )
        
        # Log the change for audit trail
        logger.info(f"Feature flag {flag_name} {action}")
        
        # Return updated status
        enabled = feature_flags.is_enabled(flag_name)
        all_flags = feature_flags.get_all_flags()
        flag_status = all_flags.get(flag_name.lower(), "unknown")
        
        return FeatureFlagStatus(
            flag_name=flag_name,
            enabled=enabled,
            status=str(flag_status)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling feature flag {request.flag_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error toggling feature flag {request.flag_name}"
        )


@router.post("/feature-flags/emergency-rollback")
def emergency_rollback_all_flags() -> Dict[str, Any]:
    """
    EMERGENCY: Disable all feature flags for immediate rollback.
    
    This endpoint should only be used in emergency situations where
    new features are causing critical issues.
    
    Returns:
        Confirmation of rollback action
    """
    try:
        logger.critical("EMERGENCY ROLLBACK INITIATED via API")
        
        # Get flags before rollback for logging  
        flags_before = feature_flags.get_all_flags()
        from backend.core.feature_flags import FeatureFlagStatus as FFS
        enabled_before = sum(1 for flag in flags_before.values() 
                           if flag == FFS.ENABLED or flag is True)
        
        # Perform emergency rollback
        from backend.core.feature_flags import emergency_rollback_all
        emergency_rollback_all()
        
        # Get flags after rollback
        flags_after = feature_flags.get_all_flags()
        enabled_after = sum(1 for flag in flags_after.values() 
                          if flag == FFS.ENABLED or flag is True)
        
        logger.critical(
            f"Emergency rollback completed: {enabled_before} → {enabled_after} enabled flags"
        )
        
        return {
            "status": "rollback_completed",
            "message": "All feature flags disabled",
            "flags_disabled": enabled_before - enabled_after,
            "remaining_enabled": enabled_after,
            "timestamp": feature_flags.config.__dict__.get('_timestamp')
        }
        
    except Exception as e:
        logger.error(f"Error during emergency rollback: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during emergency rollback"
        )