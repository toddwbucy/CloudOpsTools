"""
Structured logging configuration for PCM-Ops Tools.

Provides JSON-formatted logging with correlation IDs and security-focused logging.
"""

import json
import logging
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar
from pathlib import Path

from backend.core.config import settings

# Context variable for correlation ID (used across request lifecycle)
correlation_id_ctx: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging with security context.
    """
    
    def __init__(self, include_sensitive: bool = False):
        """
        Initialize structured formatter.
        
        Args:
            include_sensitive: Whether to include potentially sensitive data in logs
        """
        super().__init__()
        self.include_sensitive = include_sensitive
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Base log structure
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add correlation ID if available
        correlation_id = correlation_id_ctx.get()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in {
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                'filename', 'module', 'lineno', 'funcName', 'created',
                'msecs', 'relativeCreated', 'thread', 'threadName',
                'processName', 'process', 'exc_info', 'exc_text', 'stack_info'
            }:
                # Filter sensitive data unless explicitly allowed
                if not self.include_sensitive and self._is_sensitive_field(key, value):
                    extra_fields[key] = "[REDACTED]"
                else:
                    extra_fields[key] = value
        
        if extra_fields:
            log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, default=self._json_default)
    
    def _is_sensitive_field(self, key: str, value: Any) -> bool:
        """Check if field contains sensitive data"""
        sensitive_keywords = {
            'password', 'secret', 'key', 'token', 'credential', 'auth',
            'session', 'cookie', 'private', 'confidential'
        }
        
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in sensitive_keywords)
    
    def _json_default(self, obj: Any) -> str:
        """JSON serializer for objects not serializable by default"""
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        return str(obj)


def setup_logging(
    log_level: str = "INFO",
    enable_json: bool = True,
    log_file: Optional[str] = None,
    include_sensitive: bool = False
) -> None:
    """
    Configure structured logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        enable_json: Whether to use JSON formatting
        log_file: Optional file path for logging
        include_sensitive: Whether to include sensitive data in logs
    """
    
    # Clear any existing handlers
    logging.root.handlers.clear()
    
    # Configure formatters
    if enable_json:
        formatter = StructuredFormatter(include_sensitive=include_sensitive)
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Reduce noise from external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)


def get_correlation_id() -> str:
    """
    Get or create a correlation ID for request tracking.
    
    Returns:
        str: Correlation ID for current context
    """
    correlation_id = correlation_id_ctx.get()
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
        correlation_id_ctx.set(correlation_id)
    return correlation_id


def set_correlation_id(correlation_id: str) -> None:
    """
    Set correlation ID for current context.
    
    Args:
        correlation_id: Correlation ID to set
    """
    correlation_id_ctx.set(correlation_id)


def get_security_logger(name: str) -> logging.Logger:
    """
    Get a logger configured for security events.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance configured for security logging
    """
    logger = logging.getLogger(f"security.{name}")
    return logger


def log_security_event(
    event_type: str,
    message: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    extra_data: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a security event with structured data.
    
    Args:
        event_type: Type of security event (auth, access, error, etc.)
        message: Human-readable message
        user_id: Optional user identifier
        ip_address: Optional IP address
        extra_data: Additional structured data
    """
    logger = get_security_logger("events")
    
    # Build security event structure
    security_data = {
        "event_type": event_type,
        "correlation_id": get_correlation_id(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    
    if user_id:
        security_data["user_id"] = user_id
    if ip_address:
        security_data["ip_address"] = ip_address
    if extra_data:
        security_data.update(extra_data)
    
    logger.info(message, extra=security_data)


# Initialize logging based on application settings
def init_application_logging() -> None:
    """Initialize logging for the FastAPI application"""
    
    # Determine if we're in development mode
    is_dev = getattr(settings, 'DEV_MODE', False)
    
    # Configure logging level
    log_level = "DEBUG" if is_dev else "INFO"
    
    # Use JSON logging in production, plain text in development
    enable_json = not is_dev
    
    # Set up logging
    setup_logging(
        log_level=log_level,
        enable_json=enable_json,
        include_sensitive=is_dev  # Only include sensitive data in dev mode
    )
    
    # Log startup message
    logger = logging.getLogger("pcm_ops_tools.startup")
    logger.info(
        "Structured logging initialized",
        extra={
            "dev_mode": is_dev,
            "json_logging": enable_json,
            "log_level": log_level,
            "correlation_id": get_correlation_id()
        }
    )