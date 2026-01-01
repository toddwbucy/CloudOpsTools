"""
Structured logging configuration with security focus.

This module provides enhanced logging capabilities with structured output,
security event tracking, and safe log formatting to prevent information leakage.
"""

import logging
import logging.config
import json
import time
import traceback
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path


class SecurityLogFilter(logging.Filter):
    """
    Filter to identify and tag security-related log events.
    
    Adds security context and ensures sensitive data is not logged.
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Add security context to relevant records
        security_keywords = [
            'authentication', 'authorization', 'credential', 'token', 'secret',
            'login', 'logout', 'csrf', 'xss', 'injection', 'attack', 'security',
            'blocked', 'unauthorized', 'forbidden', 'suspicious', 'breach'
        ]
        
        # Check if this is a security-related log
        message_lower = record.getMessage().lower()
        is_security = any(keyword in message_lower for keyword in security_keywords)
        
        if is_security:
            record.security_event = True
            record.security_level = self._determine_security_level(record, message_lower)
        else:
            record.security_event = False
            record.security_level = 'info'
        
        # Sanitize the message to prevent sensitive data leakage
        record.msg = self._sanitize_message(str(record.msg))
        
        return True
    
    def _determine_security_level(self, record: logging.LogRecord, message_lower: str) -> str:
        """Determine the security severity level"""
        if any(word in message_lower for word in ['attack', 'breach', 'unauthorized', 'blocked']):
            return 'high'
        elif any(word in message_lower for word in ['suspicious', 'failed', 'invalid']):
            return 'medium'
        else:
            return 'low'
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize log messages to prevent sensitive data exposure"""
        import re
        
        # Mask potential AWS access keys
        message = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA****', message)
        
        # Mask potential secrets/tokens (20+ alphanumeric characters)
        message = re.sub(r'\b[A-Za-z0-9+/]{20,}\b', '****', message)
        
        # Mask email addresses partially (keep first letter and domain)
        message = re.sub(r'\b([a-zA-Z])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', r'\1****@\2', message)
        
        # Mask potential passwords in key=value pairs
        message = re.sub(r'(password|secret|key|token)[\s]*[=:][\s]*[^\s]+', r'\1=****', message, flags=re.IGNORECASE)
        
        return message


class StructuredFormatter(logging.Formatter):
    """
    Structured JSON log formatter with security awareness.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add security context if present
        if hasattr(record, 'security_event') and record.security_event:
            log_entry['security'] = {
                'event': True,
                'level': getattr(record, 'security_level', 'info'),
                'category': 'security_event'
            }
        
        # Add extra context if provided
        if hasattr(record, 'extra') and record.extra:
            log_entry['extra'] = record.extra
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        
        return json.dumps(log_entry, default=str)


class PlainTextSecurityFormatter(logging.Formatter):
    """
    Plain text formatter with security sanitization.
    
    Used when structured logging is disabled but security filtering is still needed.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        # Use standard formatting but add security markers
        formatted = super().format(record)
        
        if hasattr(record, 'security_event') and record.security_event:
            security_level = getattr(record, 'security_level', 'info').upper()
            formatted = f"[SECURITY:{security_level}] {formatted}"
        
        return formatted


def setup_security_logging(enable_structured_logging: bool = False) -> None:
    """
    Set up logging configuration with security focus.
    
    Args:
        enable_structured_logging: Whether to use structured JSON logging
    """
    try:
        from backend.core.feature_flags import is_feature_enabled
        structured_enabled = is_feature_enabled('STRUCTURED_LOGGING')
    except ImportError:
        structured_enabled = enable_structured_logging
    
    # Ensure logs directory exists
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'structured': {
                '()': StructuredFormatter,
            },
            'plain_security': {
                '()': PlainTextSecurityFormatter,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            },
            'standard': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },
        'filters': {
            'security_filter': {
                '()': SecurityLogFilter,
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'structured' if structured_enabled else 'plain_security',
                'filters': ['security_filter'],
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': 'logs/cloudopstools.log',
                'maxBytes': 10485760,  # 10MB
                'backupCount': 10,
                'level': 'DEBUG',
                'formatter': 'structured' if structured_enabled else 'plain_security',
                'filters': ['security_filter'],
            },
            'security_file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': 'logs/security_events.log',
                'maxBytes': 10485760,  # 10MB
                'backupCount': 20,  # Keep more security logs
                'level': 'INFO',
                'formatter': 'structured' if structured_enabled else 'plain_security',
                'filters': ['security_filter'],
            }
        },
        'loggers': {
            '': {  # Root logger
                'level': 'INFO',
                'handlers': ['console', 'file'],
            },
            'backend.core.security': {
                'level': 'DEBUG',
                'handlers': ['security_file'],
                'propagate': True,
            },
            'backend.api.auth': {
                'level': 'DEBUG',
                'handlers': ['security_file'],
                'propagate': True,
            },
            'backend.web.aws.auth': {
                'level': 'DEBUG',
                'handlers': ['security_file'],
                'propagate': True,
            },
            'uvicorn.access': {
                'level': 'INFO',
                'handlers': ['file'],
                'propagate': False,
            },
        }
    }
    
    # Apply the configuration
    logging.config.dictConfig(logging_config)
    
    # Log that security logging is enabled
    security_logger = logging.getLogger('backend.core.security')
    if structured_enabled:
        security_logger.info("Structured security logging enabled")
    else:
        security_logger.info("Security-aware logging enabled")


def log_security_event(
    event_type: str,
    message: str,
    level: str = 'info',
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a security event with structured context.
    
    Args:
        event_type: Type of security event (e.g., 'login_attempt', 'xss_blocked')
        message: Human-readable message
        level: Security level ('low', 'medium', 'high')
        user_id: Optional user identifier
        ip_address: Optional IP address
        request_id: Optional request identifier
        extra: Optional additional context
    """
    logger = logging.getLogger('backend.core.security')
    
    # Create log record with security context
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create extra context
    log_extra = {
        'event_type': event_type,
        'security_level': level,
        'security_event': True,
    }
    
    if user_id:
        log_extra['user_id'] = user_id
    if ip_address:
        log_extra['ip_address'] = ip_address
    if request_id:
        log_extra['request_id'] = request_id
    if extra:
        log_extra['extra'] = extra
    
    # Log the event
    logger.log(log_level, message, extra=log_extra)


# Convenience functions for common security events
def log_authentication_attempt(success: bool, user_id: Optional[str] = None, ip_address: Optional[str] = None) -> None:
    """Log an authentication attempt"""
    if success:
        log_security_event(
            'authentication_success',
            f"Successful authentication for user: {user_id or 'unknown'}",
            level='low',
            user_id=user_id,
            ip_address=ip_address
        )
    else:
        log_security_event(
            'authentication_failure',
            f"Failed authentication attempt for user: {user_id or 'unknown'}",
            level='medium',
            user_id=user_id,
            ip_address=ip_address
        )


def log_xss_attempt_blocked(pattern: str, field_name: str, ip_address: Optional[str] = None) -> None:
    """Log a blocked XSS attempt"""
    log_security_event(
        'xss_attempt_blocked',
        f"Blocked XSS attempt in field '{field_name}' - pattern: {pattern}",
        level='high',
        ip_address=ip_address,
        extra={'field_name': field_name, 'blocked_pattern': pattern}
    )


def log_csrf_validation_failure(ip_address: Optional[str] = None, endpoint: Optional[str] = None) -> None:
    """Log a CSRF validation failure"""
    log_security_event(
        'csrf_validation_failure',
        f"CSRF token validation failed for endpoint: {endpoint or 'unknown'}",
        level='high',
        ip_address=ip_address,
        extra={'endpoint': endpoint}
    )


def log_credential_access(action: str, environment: str, success: bool) -> None:
    """Log credential access events"""
    level = 'low' if success else 'medium'
    log_security_event(
        'credential_access',
        f"Credential {action} for {environment} environment: {'success' if success else 'failure'}",
        level=level,
        extra={'action': action, 'environment': environment, 'success': success}
    )