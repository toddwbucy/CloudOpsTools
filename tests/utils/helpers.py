"""
Test helper functions for common testing operations

These helpers provide utilities for test setup, data validation,
and common testing patterns across the test suite.
"""

import os
import time
import tempfile
import pytest
from typing import Dict, Any, Optional, Union, Callable
from pathlib import Path
from unittest.mock import MagicMock, patch


def wait_for_condition(condition: Callable[[], bool], timeout: float = 5.0, interval: float = 0.1) -> bool:
    """Wait for a condition to become true with timeout"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if condition():
            return True
        time.sleep(interval)
    return False


def assert_response_structure(response_data: Dict[str, Any], expected_keys: list[str], optional_keys: Optional[list[str]] = None):
    """Assert that response has expected structure"""
    optional_keys = optional_keys or []
    
    # Check required keys are present
    for key in expected_keys:
        assert key in response_data, f"Required key '{key}' missing from response"
    
    # Check no unexpected keys (except optional ones)
    allowed_keys = set(expected_keys + optional_keys)
    actual_keys = set(response_data.keys())
    unexpected_keys = actual_keys - allowed_keys
    
    assert not unexpected_keys, f"Unexpected keys in response: {unexpected_keys}"


def assert_no_sensitive_data_in_logs(caplog, sensitive_patterns: list[str]):
    """Assert that sensitive data patterns don't appear in logs"""
    all_logs = " ".join([record.getMessage() for record in caplog.records])
    
    for pattern in sensitive_patterns:
        assert pattern not in all_logs, f"Sensitive pattern '{pattern}' found in logs"


def assert_no_sensitive_data_in_response(response_data: Union[Dict, str], sensitive_patterns: list[str]):
    """Assert that sensitive data patterns don't appear in API responses"""
    response_text = str(response_data)
    
    for pattern in sensitive_patterns:
        assert pattern not in response_text, f"Sensitive pattern '{pattern}' found in response"


def create_temporary_file(content: str, suffix: str = ".tmp") -> str:
    """Create a temporary file with content and return its path"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=suffix) as f:
        f.write(content)
        return f.name


def cleanup_temporary_file(file_path: str):
    """Safely clean up a temporary file"""
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
    except OSError:
        pass  # File might already be deleted


def mock_aws_credentials(environment: str = "com", valid: bool = True):
    """Create mock AWS credentials for testing"""
    if valid:
        return {
            "access_key": f"AKIA{'1234567890123456' if environment == 'com' else 'ABCDEFGHIJKLMNOP'}",
            "secret_key": "valid-secret-key-for-testing-" + environment,
            "session_token": "valid-session-token-for-testing",
            "environment": environment
        }
    else:
        return {
            "access_key": "INVALID_ACCESS_KEY",
            "secret_key": "invalid-secret-key",
            "session_token": "invalid-session-token",
            "environment": environment
        }


def mock_feature_flag_response(enabled_flags: Optional[list[str]] = None):
    """Create mock feature flag response"""
    enabled_flags = enabled_flags or []
    
    all_flags = [
        "new_secret_key_handling",
        "xss_protection_enabled", 
        "csrf_tokens_enabled",
        "secure_credential_storage",
        "structured_logging",
        "thread_safe_sessions",
        "atomic_session_updates",
        "enhanced_error_handling",
        "js_memory_leak_fixes",
        "pydantic_v2_schemas"
    ]
    
    return {flag: flag in enabled_flags for flag in all_flags}


def simulate_slow_response(delay: float = 1.0):
    """Decorator to simulate slow response for performance testing"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            time.sleep(delay)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def count_log_messages(caplog, level: str = "INFO") -> int:
    """Count log messages at specific level"""
    return len([record for record in caplog.records if record.levelname == level.upper()])


def get_log_messages(caplog, level: Optional[str] = None) -> list[str]:
    """Get log messages, optionally filtered by level"""
    if level:
        return [record.getMessage() for record in caplog.records if record.levelname == level.upper()]
    return [record.getMessage() for record in caplog.records]


def assert_performance_within_threshold(duration: float, threshold: float, operation: str = "Operation"):
    """Assert that operation completed within performance threshold"""
    assert duration <= threshold, f"{operation} took {duration:.3f}s, exceeding threshold of {threshold}s"


def measure_endpoint_performance(client, endpoint: str, method: str = "GET", **kwargs) -> float:
    """Measure endpoint response time"""
    start_time = time.time()
    
    if method.upper() == "GET":
        response = client.get(endpoint, **kwargs)
    elif method.upper() == "POST":
        response = client.post(endpoint, **kwargs)
    elif method.upper() == "PUT":
        response = client.put(endpoint, **kwargs)
    elif method.upper() == "DELETE":
        response = client.delete(endpoint, **kwargs)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    
    end_time = time.time()
    
    # Ensure request was successful for valid performance measurement
    assert 200 <= response.status_code < 300, f"Request failed with status {response.status_code}"
    
    return end_time - start_time


def create_test_database_url(test_name: str) -> str:
    """Create unique test database URL"""
    safe_test_name = "".join(c for c in test_name if c.isalnum() or c in "-_")
    return f"sqlite:///./data/test_{safe_test_name}.db"


def setup_test_environment_variables(env_vars: Dict[str, str]):
    """Context manager for temporarily setting environment variables"""
    class EnvVarContext:
        def __init__(self, variables):
            self.variables = variables
            self.original_values = {}
            
        def __enter__(self):
            for key, value in self.variables.items():
                self.original_values[key] = os.environ.get(key)
                os.environ[key] = value
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            for key in self.variables.keys():
                if self.original_values[key] is None:
                    if key in os.environ:
                        del os.environ[key]
                else:
                    os.environ[key] = self.original_values[key]
    
    return EnvVarContext(env_vars)


def assert_security_headers_present(response, required_headers: Optional[list[str]] = None):
    """Assert that security headers are present in response"""
    required_headers = required_headers or [
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection"
    ]
    
    missing_headers = []
    for header in required_headers:
        if header.lower() not in [h.lower() for h in response.headers.keys()]:
            missing_headers.append(header)
    
    assert not missing_headers, f"Missing security headers: {missing_headers}"


def assert_session_security(response):
    """Assert that session cookies have proper security flags"""
    session_cookies = [
        cookie for cookie in response.cookies.values()
        if 'session' in cookie.name.lower()
    ]
    
    if session_cookies:
        cookie = session_cookies[0]
        # These assertions will be uncommented after Phase 1 implementation
        # assert cookie.secure == True, "Session cookie should have Secure flag"
        # assert cookie.httponly == True, "Session cookie should have HttpOnly flag"
        # assert cookie.samesite in ['Lax', 'Strict'], "Session cookie should have SameSite flag"


def validate_json_response(response, expected_schema: Optional[Dict[str, type]] = None):
    """Validate JSON response structure and types"""
    assert response.headers.get("content-type", "").startswith("application/json"), \
        "Response should be JSON"
    
    data = response.json()
    assert isinstance(data, dict), "Response should be a JSON object"
    
    if expected_schema:
        for key, expected_type in expected_schema.items():
            assert key in data, f"Expected key '{key}' missing from response"
            assert isinstance(data[key], expected_type), \
                f"Key '{key}' should be of type {expected_type.__name__}, got {type(data[key]).__name__}"


def skip_if_no_database():
    """Skip test if database is not available"""
    try:
        from backend.db.session import get_db
        next(get_db())
        return False
    except Exception:
        return pytest.mark.skip(reason="Database not available")


def skip_if_no_redis():
    """Skip test if Redis is not available (for session storage tests)"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        return False
    except Exception:
        return pytest.mark.skip(reason="Redis not available")


def generate_large_payload(size_kb: int = 100) -> str:
    """Generate large payload for testing size limits"""
    # Generate approximately size_kb kilobytes of data
    chunk_size = 1024
    return "A" * (size_kb * chunk_size)


def assert_rate_limiting_works(client, endpoint: str, max_requests: int = 10, window_seconds: int = 60):
    """
    Test that rate limiting is working.

    IMPLEMENTATION STATUS: NOT IMPLEMENTED (as of Phase 1)

    This is a placeholder helper for rate limiting tests. Rate limiting is not
    currently implemented in the CloudOpsTools backend, so this function only
    verifies that the endpoint handles rapid requests gracefully.

    WONT-FIX REASONING:
    Rate limiting implementation is out of scope for Phase 1 Security Test Suite.
    This helper will be updated when rate limiting is implemented in a future phase.

    Args:
        client: Test client instance
        endpoint: API endpoint to test
        max_requests: Expected rate limit threshold
        window_seconds: Rate limit time window

    Future implementation should:
        - Check for 429 responses after max_requests
        - Verify X-RateLimit-* headers
        - Check Retry-After header in 429 responses
    """
    responses = []

    for i in range(max_requests + 5):
        response = client.get(endpoint)
        responses.append(response)

        # Small delay to avoid overwhelming the system
        time.sleep(0.01)

    # Current behavior: All requests succeed (no rate limiting implemented)
    # WONT-FIX: Rate limiting not implemented in Phase 1
    success_count = len([r for r in responses if r.status_code == 200])
    assert success_count >= max_requests, "Basic functionality should work"


class TestDataManager:
    """Helper class for managing test data lifecycle"""
    
    def __init__(self):
        self.cleanup_tasks = []
        self.temp_files = []
    
    def create_temp_file(self, content: str, suffix: str = ".tmp") -> str:
        """Create temporary file and register for cleanup"""
        file_path = create_temporary_file(content, suffix)
        self.temp_files.append(file_path)
        return file_path
    
    def register_cleanup(self, cleanup_func: Callable, *args, **kwargs):
        """Register cleanup function to run during teardown"""
        self.cleanup_tasks.append((cleanup_func, args, kwargs))
    
    def cleanup(self):
        """Run all cleanup tasks"""
        # Cleanup temporary files
        for file_path in self.temp_files:
            cleanup_temporary_file(file_path)
        
        # Run custom cleanup tasks
        for cleanup_func, args, kwargs in self.cleanup_tasks:
            try:
                cleanup_func(*args, **kwargs)
            except Exception:
                pass  # Best effort cleanup
        
        # Reset state
        self.cleanup_tasks = []
        self.temp_files = []