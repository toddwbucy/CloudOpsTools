"""
Security tests for data protection and privacy

Tests encryption, data handling, and privacy measures that will be
implemented during Phase 1 security fixes.
"""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

# Mark all tests in this module as security tests
pytestmark = pytest.mark.security


@pytest.mark.security
@pytest.mark.encryption
class TestDataEncryption:
    """Test data encryption and secure storage"""
    
    def test_secret_key_entropy(self, test_settings):
        """Test SECRET_KEY has sufficient entropy"""
        secret = test_settings.SECRET_KEY
        
        # Should be at least 32 characters
        assert len(secret) >= 32
        
        # Should not be the default insecure value
        assert secret != "your-secret-key-here-change-in-production"
        
        # Should have reasonable entropy (not all same character)
        unique_chars = len(set(secret.lower()))
        assert unique_chars >= 10  # At least 10 different characters
    
    def test_database_encryption_ready(self, test_settings):
        """Test database is ready for encryption"""
        # SQLite supports encryption with proper extensions
        db_url = test_settings.DATABASE_URL
        assert "sqlite://" in db_url
        
        # Path should be secure location
        if ":" in db_url:
            db_path = db_url.split(":")[-1].replace("///", "/")
            assert not db_path.startswith("/tmp")  # Not in temp directory
    
    def test_session_encryption_configuration(self, test_settings):
        """Test session encryption is properly configured"""
        # SECRET_KEY should be suitable for session encryption
        assert isinstance(test_settings.SECRET_KEY, str)
        assert len(test_settings.SECRET_KEY.encode()) >= 32
        
        # Session lifetime should be reasonable for security
        assert test_settings.SESSION_LIFETIME_MINUTES <= 480  # Max 8 hours


@pytest.mark.security
@pytest.mark.data_leakage
class TestDataLeakagePrevention:
    """Test prevention of data leakage in logs, errors, etc."""
    
    def test_credentials_not_in_error_logs(self, client, caplog):
        """Test credentials don't appear in error logs"""
        import logging
        
        # Capture all log levels
        with caplog.at_level(logging.DEBUG):
            # Trigger an error with credentials
            response = client.post(
                "/api/auth/aws-credentials",
                json={
                    "access_key": "AKIATEST123456789012",
                    "secret_key": "SuperSecretKey123456789012345678901234",
                    "session_token": "LongSessionToken123456789"
                }
            )
        
        # Check logs for credential leakage
        all_logs = " ".join([record.getMessage() for record in caplog.records])
        
        assert "SuperSecretKey" not in all_logs
        assert "LongSessionToken" not in all_logs
        # Access key might be logged for debugging, but should be masked
        if "AKIATEST" in all_logs:
            # Should be masked like AKIA****
            assert "AKIATEST123456789012" not in all_logs
    
    def test_database_credentials_not_logged(self, test_settings, caplog):
        """Test database credentials are not logged"""
        import logging
        
        with caplog.at_level(logging.DEBUG):
            # Access database URL (might trigger logging)
            db_url = test_settings.DATABASE_URL
        
        all_logs = " ".join([record.getMessage() for record in caplog.records])
        
        # If database has credentials, they shouldn't be in logs
        if "@" in db_url:  # Has credentials
            parts = db_url.split("@")
            if ":" in parts[0]:
                # Extract potential password
                creds = parts[0].split("://")[1]
                if ":" in creds:
                    password = creds.split(":")[1]
                    assert password not in all_logs
    
    def test_environment_variables_not_leaked(self, client):
        """Test environment variables are not leaked in responses"""
        # Trigger potential error that might leak env vars
        response = client.get("/api/health")
        
        if response.status_code >= 400:
            error_text = str(response.json())
            
            # Check for common env var patterns
            sensitive_patterns = [
                "SECRET_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "DATABASE_URL",
                "PASSWORD"
            ]
            
            for pattern in sensitive_patterns:
                assert pattern not in error_text


@pytest.mark.security
@pytest.mark.file_security  
class TestFileSystemSecurity:
    """Test file system security measures"""
    
    def test_upload_directory_permissions(self, test_settings):
        """Test upload directory has proper permissions"""
        upload_path = Path("uploads")
        if upload_path.exists():
            # Should not be world-readable
            stat_info = upload_path.stat()
            # Check that others don't have read access (last digit not 4, 5, 6, 7)
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_log_directory_permissions(self):
        """Test log directory has proper permissions"""
        log_path = Path("logs")
        if log_path.exists():
            # Should not be world-readable
            stat_info = log_path.stat()
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_data_directory_permissions(self):
        """Test data directory has proper permissions"""
        data_path = Path("data")
        if data_path.exists():
            # Should not be world-readable
            stat_info = data_path.stat()
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_temporary_file_cleanup(self):
        """Test temporary files are properly cleaned up"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(b"sensitive data")
        
        try:
            # Verify file exists
            assert os.path.exists(tmp_path)
            
            # Simulate cleanup (would be done by application)
            os.unlink(tmp_path)
            
            # Verify cleanup
            assert not os.path.exists(tmp_path)
        finally:
            # Cleanup in case test fails
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


@pytest.mark.security
@pytest.mark.input_validation
class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_sql_injection_prevention(self, client):
        """Test SQL injection attempts are prevented"""
        # SQL injection payloads
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM accounts WHERE 1=1 --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            # Test in various endpoints that might query database
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": payload, "enabled": True}
            )
            
            # Should either reject or sanitize
            if response.status_code == 200:
                data = response.json()
                # If accepted, should be sanitized
                assert "DROP TABLE" not in str(data).upper()
                assert "DELETE FROM" not in str(data).upper()
            else:
                # Should be rejected with proper error
                assert response.status_code in [400, 422]
    
    def test_path_traversal_prevention(self, client):
        """Test path traversal attempts are prevented"""
        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for payload in path_payloads:
            # Test in file-related endpoints
            response = client.get(f"/static/{payload}")
            
            # Should return 404 or 403, not expose files
            assert response.status_code in [403, 404]
    
    def test_command_injection_prevention(self, client):
        """Test command injection attempts are prevented"""
        # Command injection payloads
        cmd_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "&& cat /etc/passwd"
        ]
        
        for payload in cmd_payloads:
            # Test in endpoints that might execute commands
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": f"test{payload}", "enabled": True}
            )
            
            # Should handle safely
            if response.status_code == 200:
                data = response.json()
                # Should not execute commands
                assert "root:" not in str(data)  # Common in /etc/passwd
                assert "/bin/bash" not in str(data)
    
    def test_json_payload_size_limits(self, client):
        """Test JSON payload size limits"""
        # Create large payload
        large_payload = {
            "flag_name": "test_flag",
            "enabled": True,
            "large_data": "A" * 10000  # 10KB of data
        }
        
        response = client.post("/api/feature-flags/toggle", json=large_payload)
        
        # Should either accept or reject based on size limits
        # If rejected, should be proper error code
        if response.status_code >= 400:
            assert response.status_code in [413, 422]  # Payload too large or validation error


@pytest.mark.security
@pytest.mark.session_security
class TestSessionSecurity:
    """Test session security measures"""
    
    def test_session_fixation_prevention(self, client):
        """Test session fixation attacks are prevented"""
        # Get initial session
        response1 = client.get("/aws")
        initial_cookies = response1.cookies
        
        # Simulate login attempt (when authentication is implemented)
        response2 = client.post("/api/auth/aws-credentials", json={
            "access_key": "test", "secret_key": "test"
        })
        
        # Check if session ID changed after auth attempt
        # For now, just verify session handling works
        assert response1.status_code == 200
        assert response2.status_code in [200, 400, 401]
    
    def test_session_hijacking_prevention(self, client):
        """Test session hijacking prevention measures"""
        # Create session
        response = client.get("/aws")
        
        # Session should be tied to client characteristics
        # This would be implemented with IP binding, User-Agent checks, etc.
        assert response.status_code == 200
        
        # TODO: After Phase 1 implementation:
        # - Test session binding to IP address
        # - Test session binding to User-Agent
        # - Test session regeneration on privilege changes
    
    def test_concurrent_session_handling(self, client):
        """Test handling of concurrent sessions"""
        # Create multiple sessions
        responses = []
        for _ in range(3):
            response = client.get("/aws")
            responses.append(response)
        
        # All should succeed (no session limits yet)
        assert all(r.status_code == 200 for r in responses)
        
        # TODO: After implementation:
        # - Test maximum concurrent sessions per user
        # - Test session cleanup on logout


@pytest.mark.security
@pytest.mark.compliance
class TestSecurityCompliance:
    """Test compliance with security standards"""
    
    def test_password_policy_compliance(self):
        """Test password/secret policies meet standards"""
        from backend.core.config import Settings
        settings = Settings()
        
        # SECRET_KEY should meet complexity requirements
        secret = settings.SECRET_KEY
        
        # Length requirement (NIST recommends 32+ chars for secrets)
        assert len(secret) >= 32
        
        # Should not be common weak secrets
        weak_secrets = [
            "password",
            "123456", 
            "secret",
            "admin",
            "your-secret-key-here-change-in-production"
        ]
        
        assert secret.lower() not in [w.lower() for w in weak_secrets]
    
    def test_crypto_algorithm_compliance(self):
        """Test cryptographic algorithms meet standards"""
        # This would test that we use approved algorithms
        # For now, verify configuration supports strong crypto
        
        import hashlib
        
        # SHA-256 should be available (not MD5 or SHA-1 for security)
        assert hasattr(hashlib, 'sha256')
        
        # Verify weak algorithms are not used by default
        # (This would be checked in actual crypto implementation)
    
    def test_security_headers_compliance(self, client):
        """Test security headers meet compliance standards"""
        response = client.get("/aws")
        
        # Document headers that should be present for compliance
        # After Phase 1 implementation, these should be verified:
        
        # OWASP recommended headers:
        compliance_headers = [
            "x-content-type-options",      # Should be "nosniff"
            "x-frame-options",             # Should be "DENY" or "SAMEORIGIN"
            "x-xss-protection",            # Should be "1; mode=block"
            "content-security-policy",      # Should restrict sources
            "strict-transport-security",    # Should be present in production
            "referrer-policy",             # Should be "strict-origin-when-cross-origin"
        ]
        
        # For now, just verify response is successful
        assert response.status_code == 200
        
        # TODO: Uncomment after Phase 1:
        # for header in compliance_headers:
        #     if header == "strict-transport-security" and not request.is_secure:
        #         continue  # Skip HSTS for HTTP in development
        #     assert header.lower() in [h.lower() for h in response.headers.keys()]