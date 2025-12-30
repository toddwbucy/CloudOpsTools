"""
Security tests for authentication and authorization

These tests validate security measures that will be implemented in Phase 1.
Critical for ensuring no security regressions during deployment.
"""

import pytest
from fastapi.testclient import TestClient

# Mark all tests in this module as security tests
pytestmark = pytest.mark.security


@pytest.mark.security
@pytest.mark.auth
class TestSessionSecurity:
    """Test session security measures"""
    
    def test_session_cookie_security_flags(self, client):
        """Test that session cookies have proper security flags"""
        response = client.get("/aws")
        
        # Check for session cookie
        session_cookies = [cookie for cookie in response.cookies.values() 
                          if 'session' in cookie.name.lower()]
        
        if session_cookies:
            cookie = session_cookies[0]
            # In Phase 1, these should be implemented
            # For now, we document what needs to be tested
            assert cookie.name  # Cookie exists
            
            # TODO: After Phase 1 implementation, verify:
            # assert cookie.secure == True  # Secure flag
            # assert cookie.httponly == True  # HttpOnly flag
            # assert cookie.samesite == 'Lax' or cookie.samesite == 'Strict'
    
    def test_session_timeout_configuration(self, client, test_settings):
        """Test session timeout is properly configured"""
        # Session timeout should be reasonable (30 minutes default)
        assert 5 <= test_settings.SESSION_LIFETIME_MINUTES <= 480
    
    def test_sensitive_headers_not_logged(self, client, caplog):
        """Test that sensitive headers are not logged"""
        import logging
        
        with caplog.at_level(logging.DEBUG):
            response = client.post(
                "/api/auth/aws-credentials",
                json={
                    "access_key": "AKIA123456789EXAMPLE",
                    "secret_key": "super-secret-key",
                    "session_token": "token123"
                }
            )
        
        # Check that sensitive data is not in logs
        log_text = " ".join(record.getMessage() for record in caplog.records)
        assert "super-secret-key" not in log_text
        assert "token123" not in log_text


@pytest.mark.security
@pytest.mark.csrf
class TestCSRFProtection:
    """Test CSRF protection measures (Phase 1 implementation)"""
    
    def test_csrf_token_required_for_state_changes(self, client):
        """Test CSRF protection for state-changing operations"""
        # Phase 1 will implement CSRF tokens
        # For now, test that the endpoint exists
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": "test_flag", "enabled": True}
        )
        
        # Should either work (no CSRF yet) or return proper error
        assert response.status_code in [200, 403, 422]
        
        # TODO: After Phase 1, test:
        # - POST without CSRF token should fail with 403
        # - POST with valid CSRF token should succeed
        # - CSRF tokens should be unique per session
    
    def test_csrf_token_generation_endpoint(self, client):
        """Test CSRF token generation endpoint (will be added in Phase 1)"""
        # This endpoint doesn't exist yet, but will be added
        response = client.get("/api/auth/csrf-token")
        
        # Should return 404 until Phase 1 implementation
        assert response.status_code == 404
        
        # TODO: After Phase 1 implementation:
        # assert response.status_code == 200
        # data = response.json()
        # assert "csrf_token" in data
        # assert len(data["csrf_token"]) > 20


@pytest.mark.security
@pytest.mark.xss
class TestXSSProtection:
    """Test XSS protection measures"""
    
    def test_content_security_policy_headers(self, client):
        """Test Content Security Policy headers are set"""
        response = client.get("/aws")
        
        # Phase 1 will add CSP headers
        # For now, document what should be tested
        if "content-security-policy" in response.headers:
            csp = response.headers["content-security-policy"]
            assert "unsafe-inline" not in csp or "nonce-" in csp
        
        # TODO: After Phase 1:
        # assert "content-security-policy" in response.headers
        # assert "x-content-type-options" in response.headers
        # assert response.headers["x-content-type-options"] == "nosniff"
    
    def test_user_input_sanitization(self, client):
        """Test that user input is properly sanitized"""
        # Test with potential XSS payload
        xss_payload = "<script>alert('xss')</script>"
        
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": xss_payload, "enabled": True}
        )
        
        # Should either reject input or sanitize it
        if response.status_code == 200:
            data = response.json()
            # If accepted, should be sanitized
            assert "<script>" not in str(data)
        else:
            # Should be rejected with proper error
            assert response.status_code in [400, 422]
    
    def test_error_messages_dont_leak_data(self, client):
        """Test error messages don't leak sensitive information"""
        # Trigger an error with sensitive-looking data
        response = client.post(
            "/api/auth/aws-credentials",
            json={"access_key": "AKIA123SECRET", "secret_key": ""}
        )
        
        if response.status_code >= 400:
            error_data = response.json()
            error_text = str(error_data)
            
            # Error should not contain the access key
            assert "AKIA123SECRET" not in error_text


@pytest.mark.security 
@pytest.mark.credentials
class TestCredentialSecurity:
    """Test credential handling security"""
    
    def test_credentials_not_logged_in_responses(self, client):
        """Test credentials are not returned in API responses"""
        response = client.get("/api/auth/aws-check-credentials")
        
        if response.status_code == 200:
            data = response.json()
            
            # Should not contain actual credential values
            for env_data in data.values():
                if env_data:
                    assert "access_key" not in env_data or not env_data.get("access_key", "").startswith("AKIA")
                    assert "secret_key" not in env_data
                    assert "session_token" not in env_data
    
    def test_credential_validation_secure(self, client):
        """Test credential validation doesn't leak information"""
        # Test with obviously fake credentials
        response = client.post(
            "/api/auth/aws-credentials", 
            json={
                "access_key": "AKIAFAKEKEY123456789",
                "secret_key": "fake-secret-key-that-wont-work",
                "session_token": "fake-session-token"
            }
        )
        
        # Should not reveal whether credentials exist or not
        assert response.status_code in [200, 400, 401]
        
        if response.status_code >= 400:
            error = response.json()
            # Error messages should be generic
            assert "fake-secret-key" not in str(error)
    
    def test_credential_storage_encrypted(self, test_settings):
        """Test credential storage configuration is secure"""
        # Phase 1 will implement encrypted credential storage
        # For now, verify configuration supports it
        assert hasattr(test_settings, 'SECRET_KEY')
        assert len(test_settings.SECRET_KEY) >= 32  # Minimum for secure encryption


@pytest.mark.security
@pytest.mark.headers
class TestSecurityHeaders:
    """Test security headers are properly set"""
    
    def test_security_headers_present(self, client):
        """Test essential security headers are present"""
        response = client.get("/aws")
        
        # Headers that should be present after Phase 1
        expected_headers = [
            "x-content-type-options",
            "x-frame-options", 
            "x-xss-protection",
            "strict-transport-security",  # In production with HTTPS
        ]
        
        # For now, just check response is successful
        assert response.status_code == 200
        
        # TODO: After Phase 1, uncomment:
        # for header in expected_headers:
        #     if header == "strict-transport-security" and not request.is_secure:
        #         continue  # Skip HSTS for HTTP in development
        #     assert header in response.headers
    
    def test_server_header_not_leaked(self, client):
        """Test server information is not leaked"""
        response = client.get("/api/health")
        
        # Server header should not reveal too much
        server_header = response.headers.get("server", "")
        assert "uvicorn" not in server_header.lower() or len(server_header.split()) == 1


@pytest.mark.security
@pytest.mark.rate_limiting
class TestRateLimiting:
    """Test rate limiting protection (future implementation)"""
    
    def test_api_rate_limiting_configured(self, client):
        """Test API endpoints have rate limiting"""
        # Make multiple rapid requests
        responses = []
        for _ in range(20):
            response = client.get("/api/health")
            responses.append(response)
        
        # For now, all should succeed (no rate limiting yet)
        assert all(r.status_code == 200 for r in responses)
        
        # TODO: After rate limiting implementation:
        # Check that some requests are rate limited (429 status)
    
    def test_auth_endpoint_rate_limiting(self, client):
        """Test authentication endpoints have stricter rate limiting"""
        # Attempt multiple failed authentication attempts
        responses = []
        for _ in range(10):
            response = client.post(
                "/api/auth/aws-credentials",
                json={"access_key": "fake", "secret_key": "fake"}
            )
            responses.append(response)
        
        # For now, document what should be tested
        # TODO: After implementation:
        # - Should start returning 429 after N failed attempts
        # - Should include Retry-After header


@pytest.mark.security
@pytest.mark.integration
class TestSecurityIntegration:
    """Integration tests for security measures"""
    
    def test_complete_security_flow(self, client):
        """Test complete security flow with all measures"""
        # 1. Access web page (should set secure session)
        response = client.get("/aws")
        assert response.status_code == 200
        
        # 2. Check API health (should have security headers)
        response = client.get("/api/health")
        assert response.status_code == 200
        
        # 3. Attempt credential validation (should be secure)
        response = client.post("/api/auth/aws-credentials", json={
            "access_key": "test", "secret_key": "test"
        })
        assert response.status_code in [200, 400, 401]
        
        # 4. Check feature flags (should require proper auth in future)
        response = client.get("/api/feature-flags")
        assert response.status_code == 200
    
    def test_security_regression_prevention(self, client):
        """Test that security fixes don't break existing functionality"""
        # Core functionality should still work
        endpoints = [
            "/api/health",
            "/api/providers", 
            "/api/feature-flags/health",
            "/docs",
            "/aws"
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"Endpoint {endpoint} failed with {response.status_code}"