"""
Security utilities for PCM-Ops Tools

This module provides security-related utility functions including
secure secret key generation, input validation, and data sanitization.
"""

import secrets
import string
import os
from typing import Optional
import logging
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import hashlib
import hmac
import time
from contextvars import ContextVar

logger = logging.getLogger(__name__)

# Context variable to store the current request's nonce
_request_nonce: ContextVar[str] = ContextVar('request_nonce', default="")


def generate_secure_secret_key(length: int = 64) -> str:
    """
    Generate a cryptographically secure secret key.
    
    Args:
        length: Length of the secret key (default: 64 characters)
        
    Returns:
        A secure random string suitable for use as a SECRET_KEY
    """
    # Use a mix of letters, digits, and safe symbols for maximum entropy
    alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_or_create_secret_key() -> str:
    """
    Get SECRET_KEY from environment or generate a new secure one.
    
    This function implements the new secure secret key handling:
    1. First, check if SECRET_KEY is set in environment variables
    2. If not found, check for a secret key file
    3. If neither exists, generate a new secure key and save it
    4. Always validate that the key meets security requirements
    
    Returns:
        A secure secret key string
        
    Raises:
        ValueError: If the secret key doesn't meet security requirements
    """
    secret_key = None
    
    # 1. Try environment variable first (highest priority)
    secret_key = os.environ.get("SECRET_KEY")
    if secret_key:
        logger.info("Using SECRET_KEY from environment variable")
        validate_secret_key(secret_key)
        return secret_key
    
    # 2. Try secret key file
    secret_file_path = "data/.secret_key"
    if os.path.exists(secret_file_path):
        try:
            with open(secret_file_path, 'r') as f:
                secret_key = f.read().strip()
            if secret_key:
                logger.info("Using SECRET_KEY from secret file")
                validate_secret_key(secret_key)
                return secret_key
        except Exception as e:
            logger.warning(f"Could not read secret key file: {e}")
    
    # 3. Generate new secure key and save it
    logger.warning("No secure SECRET_KEY found, generating new one")
    secret_key = generate_secure_secret_key()
    
    # Save to file for persistence
    try:
        os.makedirs("data", exist_ok=True)
        with open(secret_file_path, 'w') as f:
            f.write(secret_key)
        # Set secure file permissions (cross-platform)
        _set_secure_file_permissions(secret_file_path)
        logger.info("Generated new SECRET_KEY and saved to secure file")
    except Exception as e:
        logger.error(f"Could not save secret key to file: {e}")
        logger.warning("Using generated key in memory only (will regenerate on restart)")
    
    validate_secret_key(secret_key)
    return secret_key


def validate_secret_key(secret_key: str) -> None:
    """
    Validate that a secret key meets security requirements.
    
    Args:
        secret_key: The secret key to validate
        
    Raises:
        ValueError: If the secret key doesn't meet requirements
    """
    if not secret_key:
        raise ValueError("SECRET_KEY cannot be empty")
    
    if len(secret_key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters long")
    
    # Check for obviously insecure default values
    insecure_defaults = [
        "your-secret-key-here-change-in-production",
        "change-me",
        "secret",
        "password",
        "123456",
        "admin"
    ]
    
    if secret_key.lower() in [default.lower() for default in insecure_defaults]:
        raise ValueError("SECRET_KEY appears to be an insecure default value")
    
    # Check for sufficient entropy (at least 8 different characters)
    unique_chars = len(set(secret_key.lower()))
    if unique_chars < 8:
        raise ValueError("SECRET_KEY has insufficient entropy (too repetitive)")
    
    logger.debug("SECRET_KEY validation passed")


def _set_secure_file_permissions(file_path: str) -> None:
    """
    Set secure file permissions on Linux/POSIX systems.
    
    Sets 0o600 (owner read/write only) for maximum security.
    Designed for container deployment environments (AWS Fargate, WSL).
    
    Args:
        file_path: Path to the file to secure
    """
    try:
        # Set restrictive POSIX permissions: owner read/write only
        os.chmod(file_path, 0o600)
        logger.debug(f"Set secure file permissions 0o600 on {file_path}")
        
    except Exception as e:
        logger.warning(f"Could not set secure file permissions on {file_path}: {e}")
        logger.info("File created but permissions may not be optimal for security")


def sanitize_log_data(data: str, max_length: int = 100) -> str:
    """
    Sanitize data for safe logging.
    
    Args:
        data: The data to sanitize
        max_length: Maximum length to log
        
    Returns:
        Sanitized data safe for logging
    """
    if not data:
        return ""
    
    # Truncate if too long
    if len(data) > max_length:
        data = data[:max_length] + "..."
    
    # Remove potential secret patterns
    import re
    
    # Mask AWS access keys
    data = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA****', data)
    
    # Mask potential secrets/tokens
    data = re.sub(r'\b[A-Za-z0-9+/]{20,}\b', '****', data)
    
    # Remove potential passwords
    data = re.sub(r'(?i)(password|secret|key|token)[\'"\s]*[:=][\'"\s]*[^\s\'"]+', 
                  r'\1=****', data)
    
    return data


def sanitize_error_message(error_msg: str) -> str:
    """
    Sanitize error messages to prevent sensitive data leakage.
    
    Args:
        error_msg: The raw error message to sanitize
        
    Returns:
        A sanitized error message safe for API responses
    """
    if not error_msg:
        return "Unknown error occurred"
    
    # Convert to string if needed
    error_msg = str(error_msg)
    
    # List of patterns that might indicate sensitive data
    sensitive_patterns = [
        # AWS access keys
        (r'AKIA[A-Z0-9]{16}', 'AKIA****'),
        # Potential secret keys (20+ alphanumeric characters)
        (r'\b[A-Za-z0-9+/]{20,}\b', '****'),
        # Token patterns
        (r'token[\'"\s]*[:=][\'"\s]*[^\s\'"]+', 'token=****'),
        # Key patterns
        (r'key[\'"\s]*[:=][\'"\s]*[^\s\'"]+', 'key=****'),
        # Password patterns
        (r'password[\'"\s]*[:=][\'"\s]*[^\s\'"]+', 'password=****'),
    ]
    
    sanitized = error_msg
    for pattern, replacement in sensitive_patterns:
        import re
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    # Truncate very long error messages
    if len(sanitized) > 200:
        sanitized = sanitized[:200] + "..."
    
    return sanitized


def create_safe_error_response(error: Exception, default_message: str = "Operation failed") -> str:
    """
    Create a safe error response that doesn't leak sensitive information.
    
    Args:
        error: The exception that occurred
        default_message: Default message to use if sanitization removes everything
        
    Returns:
        A safe error message for API responses
    """
    from backend.core.feature_flags import is_feature_enabled
    
    # If XSS protection is enabled, use sanitized messages
    if is_feature_enabled('XSS_PROTECTION_ENABLED'):
        # Classify the error type for safe messaging
        error_str = str(error).lower()
        
        if 'invalid' in error_str and ('key' in error_str or 'token' in error_str):
            return "Invalid credentials provided"
        elif 'access denied' in error_str or 'forbidden' in error_str:
            return "Access denied - please check your permissions"
        elif 'expired' in error_str:
            return "Credentials have expired"
        elif 'network' in error_str or 'connection' in error_str:
            return "Network connection error"
        else:
            return default_message
    else:
        # Legacy behavior - return sanitized but more detailed message
        return sanitize_error_message(str(error))


def mask_sensitive_data(data: dict, sensitive_keys: Optional[list] = None) -> dict:
    """
    Mask sensitive data in dictionaries for safe logging/responses.
    
    Args:
        data: Dictionary containing potentially sensitive data
        sensitive_keys: List of keys to mask (uses defaults if None)
        
    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = [
            'secret_key', 'password', 'token', 'access_key',
            'secret', 'key', 'credential', 'auth', 'session_token'
        ]
    
    masked_data = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            if isinstance(value, str) and value:
                # Show first 4 characters for identification, mask the rest
                if len(value) > 8:
                    masked_data[key] = value[:4] + "****"
                else:
                    masked_data[key] = "****"
            else:
                masked_data[key] = "****"
        else:
            masked_data[key] = value
    
    return masked_data


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers for XSS and other attack prevention.
    
    Only adds headers when XSS_PROTECTION_ENABLED feature flag is enabled.
    Uses nonce-based CSP to prevent 'unsafe-inline' vulnerabilities.
    """
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce for CSP"""
        return secrets.token_urlsafe(32)
    
    async def dispatch(self, request: Request, call_next):
        # Check if XSS protection is enabled
        try:
            from backend.core.feature_flags import is_feature_enabled
            if not is_feature_enabled('XSS_PROTECTION_ENABLED'):
                return await call_next(request)
        except ImportError:
            # Feature flags not available, skip security headers
            return await call_next(request)
        
        # Generate a nonce for this request
        nonce = self._generate_nonce()
        _request_nonce.set(nonce)
        
        response = await call_next(request)
        
        # Add security headers to prevent XSS and other attacks
        security_headers = {
            # Prevent XSS attacks
            "X-XSS-Protection": "1; mode=block",
            
            # Prevent content type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Content Security Policy with nonce (no 'unsafe-inline' for scripts)
            "Content-Security-Policy": (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}' cdn.jsdelivr.net unpkg.com; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "font-src 'self' cdn.jsdelivr.net; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "form-action 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'"
            ),
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy (formerly Feature-Policy)
            "Permissions-Policy": (
                "camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=(), "
                "accelerometer=(), ambient-light-sensor=()"
            )
        }
        
        # Add all security headers to the response
        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value
        
        return response


def get_current_nonce() -> str:
    """
    Get the current request's nonce for use in templates.
    
    Returns:
        The current request's nonce, or empty string if not available
    """
    try:
        return _request_nonce.get()
    except LookupError:
        # No nonce set for current request
        return ""


def validate_and_sanitize_input(input_data: str, field_name: str = "input") -> str:
    """
    Validate and sanitize user input to prevent XSS attacks.
    
    Args:
        input_data: The input data to validate and sanitize
        field_name: Name of the field for error messages
        
    Returns:
        Sanitized input data
        
    Raises:
        ValueError: If input contains dangerous content
    """
    if not input_data or not isinstance(input_data, str):
        return ""
    
    # Strip whitespace
    sanitized = input_data.strip()
    
    # Check for XSS patterns
    dangerous_patterns = [
        '<script', '</script', 'javascript:', 'data:text/html',
        'vbscript:', '<iframe', '<object', '<embed', '<link',
        'onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=',
        'onblur=', 'onchange=', 'onsubmit=', 'onreset=', 'onselect=',
        'onkeydown=', 'onkeypress=', 'onkeyup=', 'expression('
    ]
    
    # Convert to lowercase for case-insensitive checking
    lower_input = sanitized.lower()
    
    # Check for dangerous patterns
    for pattern in dangerous_patterns:
        if pattern in lower_input:
            logger.warning(f"Blocked potentially dangerous input in {field_name}: pattern '{pattern}' detected")
            
            # Log security event
            try:
                from backend.core.logging_config import log_xss_attempt_blocked
                log_xss_attempt_blocked(pattern, field_name)
            except ImportError:
                pass  # Logging not available during early initialization
                
            raise ValueError(f"Invalid characters detected in {field_name}")
    
    # Additional checks for common XSS vectors
    if any(char in sanitized for char in ['<', '>', '"', "'", '&']):
        # HTML encode these characters
        sanitized = (sanitized.replace('&', '&amp;')
                              .replace('<', '&lt;')
                              .replace('>', '&gt;')
                              .replace('"', '&quot;')
                              .replace("'", '&#x27;'))
        logger.debug(f"HTML-encoded special characters in {field_name}")
    
    return sanitized


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to provide CSRF token protection for state-changing operations.
    
    Only applies protection when CSRF_TOKENS_ENABLED feature flag is enabled.
    """
    
    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self.secret_key = secret_key.encode('utf-8')
    
    async def dispatch(self, request: Request, call_next):
        # Check if CSRF protection is enabled
        try:
            from backend.core.feature_flags import is_feature_enabled
            if not is_feature_enabled('CSRF_TOKENS_ENABLED'):
                return await call_next(request)
        except ImportError:
            # Feature flags not available, skip CSRF protection
            return await call_next(request)
        
        # Only protect state-changing operations
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Check for valid CSRF token
            if not await self._validate_csrf_token(request):
                logger.warning(f"CSRF token validation failed for {request.method} {request.url}")
                
                # Log security event
                try:
                    from backend.core.logging_config import log_csrf_validation_failure
                    log_csrf_validation_failure(
                        ip_address=request.client.host if request.client else None,
                        endpoint=str(request.url.path)
                    )
                except ImportError:
                    pass  # Logging not available during early initialization
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token validation failed"
                )
        
        response = await call_next(request)
        
        # Add CSRF token to response if it's a page request
        if request.method == 'GET' and 'text/html' in request.headers.get('accept', ''):
            csrf_token = self._generate_csrf_token()
            response.headers['X-CSRF-Token'] = csrf_token
        
        return response
    
    def _generate_csrf_token(self) -> str:
        """Generate a CSRF token with timestamp"""
        timestamp = str(int(time.time()))
        random_part = secrets.token_urlsafe(32)
        message = f"{timestamp}:{random_part}"
        signature = hmac.new(
            self.secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"{message}:{signature}"
    
    async def _validate_csrf_token(self, request: Request) -> bool:
        """Validate CSRF token from request"""
        # Get token from header or form data
        csrf_token = request.headers.get('X-CSRF-Token')
        
        if not csrf_token:
            # Try to get from form data for form submissions
            try:
                form_data = await request.form()
                csrf_token = form_data.get('csrf_token')
            except Exception:
                pass
        
        if not csrf_token:
            return False
        
        try:
            # Parse token components
            parts = csrf_token.split(':')
            if len(parts) != 3:
                return False
            
            timestamp, random_part, signature = parts
            message = f"{timestamp}:{random_part}"
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key,
                message.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
            
            # Check if token is not too old (1 hour max)
            token_time = int(timestamp)
            current_time = int(time.time())
            if current_time - token_time > 3600:  # 1 hour
                logger.debug("CSRF token expired")
                return False
            
            return True
            
        except Exception as e:
            logger.debug(f"CSRF token validation error: {e}")
            return False


def generate_csrf_token_for_template() -> str:
    """
    Generate a CSRF token for use in templates.
    
    This function can be called directly from templates or view functions
    to generate CSRF tokens for form inclusion.
    """
    try:
        from backend.core.feature_flags import is_feature_enabled
        if not is_feature_enabled('CSRF_TOKENS_ENABLED'):
            return ""
    except ImportError:
        return ""
    
    from backend.core.config import settings
    secret_key = settings.SECRET_KEY.encode('utf-8')
    
    timestamp = str(int(time.time()))
    random_part = secrets.token_urlsafe(32)
    message = f"{timestamp}:{random_part}"
    signature = hmac.new(
        secret_key,
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"{message}:{signature}"


def validate_csrf_token_manual(csrf_token: str) -> bool:
    """
    Manually validate a CSRF token (for use in route handlers).
    
    Args:
        csrf_token: The CSRF token to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        from backend.core.feature_flags import is_feature_enabled
        if not is_feature_enabled('CSRF_TOKENS_ENABLED'):
            return True  # Skip validation if feature is disabled
    except ImportError:
        return True
    
    if not csrf_token:
        return False
    
    try:
        from backend.core.config import settings
        secret_key = settings.SECRET_KEY.encode('utf-8')
        
        # Parse token components
        parts = csrf_token.split(':')
        if len(parts) != 3:
            return False
        
        timestamp, random_part, signature = parts
        message = f"{timestamp}:{random_part}"
        
        # Verify signature
        expected_signature = hmac.new(
            secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return False
        
        # Check if token is not too old (1 hour max)
        token_time = int(timestamp)
        current_time = int(time.time())
        if current_time - token_time > 3600:  # 1 hour
            return False
        
        return True
        
    except Exception as e:
        logger.debug(f"Manual CSRF token validation error: {e}")
        return False