"""
Centralized credential validation helpers for PCM-Ops Tools.

Provides reusable credential validation decorators and utilities to eliminate
code duplication across AWS provider modules.
"""

import functools
import logging
from typing import Optional, Callable, Any, Dict
from fastapi import HTTPException

from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.core.utils.logging_config import log_security_event

logger = logging.getLogger("pcm_ops_tools.credentials")


def get_credential_manager() -> CredentialManager:
    """
    Get the credential manager instance.
    
    Returns:
        CredentialManager instance
    """
    return CredentialManager.get_instance()


def validate_aws_credentials(
    environment: str, 
    credential_manager: Optional[CredentialManager] = None
) -> bool:
    """
    Validate AWS credentials for the specified environment.
    
    Args:
        environment: AWS environment ('com' or 'gov')
        credential_manager: Optional credential manager instance
        
    Returns:
        bool: True if credentials are valid, False otherwise
    """
    try:
        if credential_manager is None:
            credential_manager = get_credential_manager()
        
        is_valid = credential_manager.are_credentials_valid(environment)
        
        # Log credential validation attempt (without sensitive details)
        log_security_event(
            event_type="credential_validation",
            message=f"AWS credential validation for {environment}",
            extra_data={
                "environment": environment,
                "validation_result": is_valid,
                "credential_source": "credential_manager"
            }
        )
        
        return is_valid
        
    except Exception as e:
        logger.error(f"Error validating credentials for {environment}: {e}")
        log_security_event(
            event_type="credential_validation_error",
            message=f"AWS credential validation failed for {environment}",
            extra_data={
                "environment": environment,
                "error_type": type(e).__name__,
                "error_message": str(e)
            }
        )
        return False


def require_valid_credentials(
    environment: Optional[str] = None,
    error_message: Optional[str] = None,
    status_code: int = 401
):
    """
    Decorator that requires valid AWS credentials for the specified environment.
    
    Args:
        environment: AWS environment to validate ('com' or 'gov'). If None, will try to extract from request
        error_message: Custom error message for credential validation failure
        status_code: HTTP status code to return on failure (default: 401)
    
    Usage:
        @require_valid_credentials(environment="com")
        def my_endpoint():
            # This will only execute if COM credentials are valid
            pass
            
        @require_valid_credentials()
        def my_endpoint(environment: str):
            # This will validate credentials for the provided environment parameter
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Determine environment to validate
            env_to_validate = environment
            
            # If no environment specified, try to extract from function parameters
            if env_to_validate is None:
                if 'environment' in kwargs:
                    env_to_validate = kwargs['environment']
                else:
                    # Check if environment is in function signature
                    import inspect
                    sig = inspect.signature(func)
                    if 'environment' in sig.parameters and args:
                        # Try to match positional arguments with parameter names
                        param_names = list(sig.parameters.keys())
                        if len(args) > param_names.index('environment'):
                            env_to_validate = args[param_names.index('environment')]
            
            if env_to_validate is None:
                raise HTTPException(
                    status_code=400,
                    detail="Environment parameter is required for credential validation"
                )
            
            # Validate credentials
            if not validate_aws_credentials(env_to_validate):
                error_msg = error_message or f"Invalid or missing AWS credentials for {env_to_validate} environment"
                raise HTTPException(status_code=status_code, detail=error_msg)
            
            # Credentials are valid, proceed with function execution
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def check_multiple_environments(environments: list[str]) -> Dict[str, bool]:
    """
    Check credential validity for multiple AWS environments.
    
    Args:
        environments: List of AWS environments to check
        
    Returns:
        Dict mapping environment names to their validity status
    """
    credential_manager = get_credential_manager()
    results = {}
    
    for env in environments:
        try:
            results[env] = validate_aws_credentials(env, credential_manager)
        except Exception as e:
            logger.error(f"Error checking credentials for {env}: {e}")
            results[env] = False
    
    return results


def get_credential_status_summary() -> Dict[str, Any]:
    """
    Get a summary of credential status for all AWS environments.
    
    Returns:
        Dict containing credential status summary
    """
    environments = ["com", "gov"]
    credential_status = check_multiple_environments(environments)
    
    valid_envs = [env for env, valid in credential_status.items() if valid]
    invalid_envs = [env for env, valid in credential_status.items() if not valid]
    
    summary = {
        "total_environments": len(environments),
        "valid_environments": len(valid_envs),
        "invalid_environments": len(invalid_envs),
        "environment_status": credential_status,
        "has_any_valid": len(valid_envs) > 0,
        "all_valid": len(valid_envs) == len(environments)
    }
    
    return summary


class CredentialValidationMixin:
    """
    Mixin class that provides credential validation methods for FastAPI route classes.
    
    Usage:
        class MyRoutes(CredentialValidationMixin):
            def my_endpoint(self, environment: str):
                if not self.validate_credentials(environment):
                    raise HTTPException(401, "Invalid credentials")
                # Proceed with authenticated logic
    """
    
    def __init__(self):
        self.credential_manager = get_credential_manager()
    
    def validate_credentials(self, environment: str) -> bool:
        """Validate credentials for the specified environment"""
        return validate_aws_credentials(environment, self.credential_manager)
    
    def require_credentials(self, environment: str, error_message: Optional[str] = None):
        """
        Require valid credentials or raise HTTPException.
        
        Args:
            environment: Environment to validate
            error_message: Optional custom error message
            
        Raises:
            HTTPException: If credentials are not valid
        """
        if not self.validate_credentials(environment):
            error_msg = error_message or f"Invalid or missing AWS credentials for {environment} environment"
            raise HTTPException(status_code=401, detail=error_msg)
    
    def get_environments_with_valid_credentials(self) -> list[str]:
        """Get list of environments with valid credentials"""
        status = check_multiple_environments(["com", "gov"])
        return [env for env, valid in status.items() if valid]


# Utility functions for backward compatibility
def are_credentials_valid(environment: str) -> bool:
    """
    Backward compatibility function for existing code.
    
    Args:
        environment: AWS environment to validate
        
    Returns:
        bool: True if credentials are valid
    """
    return validate_aws_credentials(environment)


def get_valid_environments() -> list[str]:
    """
    Get list of AWS environments with valid credentials.
    
    Returns:
        List of environment names with valid credentials
    """
    status = check_multiple_environments(["com", "gov"])
    return [env for env, valid in status.items() if valid]