"""
Test data factories for consistent test data generation

These factories create realistic test data for various scenarios
including security testing, credential management, and API validation.
"""

import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class AWSCredentialsFactory:
    """Factory for creating AWS credential test data"""
    
    @staticmethod
    def create_valid_credentials(environment: str = "com") -> Dict[str, Any]:
        """Create valid-looking AWS credentials for testing"""
        return {
            "access_key": f"AKIA{''.join([str(i) for i in range(16)])}",
            "secret_key": "".join([chr(97 + (i % 26)) for i in range(40)]),  # 40 lowercase chars
            "session_token": f"IQoJb3JpZ2luX2VjE{''.join([str(i) for i in range(100)])}...",
            "environment": environment,
            "region": "us-east-1" if environment == "com" else "us-gov-west-1"
        }
    
    @staticmethod
    def create_expired_credentials(environment: str = "com") -> Dict[str, Any]:
        """Create expired AWS credentials for testing"""
        credentials = AWSCredentialsFactory.create_valid_credentials(environment)
        credentials["expiration"] = int((datetime.now() - timedelta(hours=1)).timestamp())
        return credentials
    
    @staticmethod
    def create_invalid_credentials() -> Dict[str, Any]:
        """Create obviously invalid credentials for security testing"""
        return {
            "access_key": "INVALID_KEY_123",
            "secret_key": "invalid-secret-key-for-testing",
            "session_token": "invalid-token",
            "environment": "com",
            "region": "us-east-1"
        }
    
    @staticmethod
    def create_malicious_credentials() -> Dict[str, Any]:
        """Create credentials with potential injection attempts"""
        return {
            "access_key": "AKIA'; DROP TABLE users; --",
            "secret_key": "<script>alert('xss')</script>",
            "session_token": "$(cat /etc/passwd)",
            "environment": "../../../etc/passwd",
            "region": "us-east-1"
        }


class FeatureFlagFactory:
    """Factory for creating feature flag test data"""
    
    @staticmethod
    def create_security_flags() -> Dict[str, Any]:
        """Create Phase 1 security feature flags"""
        return {
            "new_secret_key_handling": False,
            "xss_protection_enabled": False,
            "csrf_tokens_enabled": False,
            "secure_credential_storage": False,
            "structured_logging": False
        }
    
    @staticmethod
    def create_development_flags() -> Dict[str, Any]:
        """Create development feature flags"""
        return {
            "debug_mode_enabled": False,
            "staging_mode_enabled": False,
            "rollback_mode_enabled": False
        }
    
    @staticmethod
    def create_all_enabled_flags() -> Dict[str, Any]:
        """Create feature flags with all flags enabled (for rollback testing)"""
        flags = FeatureFlagFactory.create_security_flags()
        flags.update(FeatureFlagFactory.create_development_flags())
        
        # Enable all flags
        return {key: True for key in flags.keys()}
    
    @staticmethod
    def create_flag_toggle_request(flag_name: str, enabled: bool) -> Dict[str, Any]:
        """Create feature flag toggle request"""
        return {
            "flag_name": flag_name,
            "enabled": enabled
        }


class SecurityTestDataFactory:
    """Factory for creating security test data"""
    
    @staticmethod
    def create_xss_payloads() -> list[str]:
        """Create XSS test payloads"""
        return [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<body onload='alert(1)'>",
            "<input onfocus='alert(1)' autofocus>",
        ]
    
    @staticmethod
    def create_sql_injection_payloads() -> list[str]:
        """Create SQL injection test payloads"""
        return [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM accounts WHERE 1=1 --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1--",
            "'; EXEC sp_helpdb; --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --"
        ]
    
    @staticmethod
    def create_path_traversal_payloads() -> list[str]:
        """Create path traversal test payloads"""
        return [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/var/log/../../../../etc/passwd",
            "....\/....\/....\/etc/passwd"
        ]
    
    @staticmethod
    def create_command_injection_payloads() -> list[str]:
        """Create command injection test payloads"""
        return [
            "; cat /etc/passwd",
            "| whoami",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "&& cat /etc/passwd",
            "; ls -la /",
            "| id",
            "$(id)",
            "`id`",
            "&& whoami"
        ]
    
    @staticmethod
    def create_sensitive_data_patterns() -> list[str]:
        """Create patterns that look like sensitive data"""
        return [
            "AKIA1234567890123456",  # AWS Access Key
            "aws_secret_access_key",
            "password123",
            "secret_key_here",
            "private_key_data",
            "session_token_12345",
            "api_key_abcdef123456",
            "bearer_token_xyz789"
        ]


class APITestDataFactory:
    """Factory for creating API test data"""
    
    @staticmethod
    def create_health_check_response() -> Dict[str, Any]:
        """Create expected health check response"""
        return {
            "status": "healthy",
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def create_providers_response() -> Dict[str, Any]:
        """Create expected providers response"""
        return {
            "providers": {
                "aws": {
                    "name": "Amazon Web Services",
                    "tools": ["script_runner", "linux_qc_patching", "sft_fixer"]
                },
                "azure": {
                    "name": "Microsoft Azure",
                    "tools": []
                },
                "gcp": {
                    "name": "Google Cloud Platform", 
                    "tools": []
                }
            }
        }
    
    @staticmethod
    def create_feature_flags_response() -> Dict[str, Any]:
        """Create expected feature flags response"""
        return {
            "new_secret_key_handling": False,
            "xss_protection_enabled": False,
            "csrf_tokens_enabled": False,
            "secure_credential_storage": False,
            "structured_logging": False
        }
    
    @staticmethod
    def create_error_response(error_code: int, message: str) -> Dict[str, Any]:
        """Create API error response"""
        return {
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
        }


class DatabaseTestDataFactory:
    """Factory for creating database test data"""
    
    @staticmethod
    def create_test_account() -> Dict[str, Any]:
        """Create test AWS account data"""
        return {
            "account_id": "123456789012",
            "account_name": f"test-account-{uuid.uuid4().hex[:8]}",
            "environment": "com",
            "region": "us-east-1",
            "status": "active"
        }
    
    @staticmethod
    def create_test_execution() -> Dict[str, Any]:
        """Create test script execution data"""
        return {
            "execution_id": str(uuid.uuid4()),
            "script_name": "test-script.sh",
            "status": "pending",
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
    
    @staticmethod
    def create_test_change() -> Dict[str, Any]:
        """Create test change record data"""
        return {
            "change_id": f"CHG{uuid.uuid4().hex[:8].upper()}",
            "title": "Test Change Record",
            "description": "Test change for validation",
            "status": "new",
            "created_at": datetime.now()
        }


class PerformanceTestDataFactory:
    """Factory for creating performance test data"""
    
    @staticmethod
    def create_load_test_requests() -> list[Dict[str, Any]]:
        """Create multiple requests for load testing"""
        return [
            {"method": "GET", "url": "/api/health"},
            {"method": "GET", "url": "/api/providers"},
            {"method": "GET", "url": "/api/feature-flags"},
            {"method": "GET", "url": "/api/feature-flags/health"},
            {"method": "GET", "url": "/docs"}
        ] * 10  # 50 total requests
    
    @staticmethod
    def create_concurrent_feature_flag_toggles() -> list[Dict[str, Any]]:
        """Create concurrent feature flag toggle requests"""
        flags = [
            "structured_logging",
            "enhanced_error_handling", 
            "xss_protection_enabled",
            "csrf_tokens_enabled",
            "secure_credential_storage"
        ]
        
        requests = []
        for flag in flags:
            requests.extend([
                {"flag_name": flag, "enabled": True},
                {"flag_name": flag, "enabled": False}
            ])
        
        return requests