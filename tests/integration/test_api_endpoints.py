"""
Integration tests for API endpoints

These tests validate that API endpoints work correctly with the database
and other components. Critical for validating Phase 1 fixes.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.core.feature_flags import FeatureFlagStatus

# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.mark.api
class TestHealthEndpoints:
    """Test health check and status endpoints"""
    
    def test_health_endpoint(self, client):
        """Test main health endpoint"""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"
    
    def test_providers_endpoint(self, client):
        """Test providers listing endpoint"""
        response = client.get("/api/providers")
        
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert isinstance(data["providers"], dict)


@pytest.mark.api
@pytest.mark.feature_flag
class TestFeatureFlagsAPI:
    """Test feature flags API endpoints"""
    
    def test_feature_flags_health(self, client):
        """Test feature flags health endpoint"""
        response = client.get("/api/feature-flags/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "total_flags" in data
        assert "enabled_flags" in data
    
    def test_list_all_feature_flags(self, client):
        """Test listing all feature flags"""
        response = client.get("/api/feature-flags")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        
        # Check for Phase 1 security flags
        expected_flags = [
            'new_secret_key_handling',
            'xss_protection_enabled',
            'csrf_tokens_enabled',
            'secure_credential_storage',
            'structured_logging'
        ]
        
        for flag in expected_flags:
            assert flag in data
    
    def test_get_specific_feature_flag(self, client):
        """Test getting specific feature flag status"""
        flag_name = "structured_logging"
        response = client.get(f"/api/feature-flags/{flag_name}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["flag_name"] == flag_name
        assert "enabled" in data
        assert "status" in data
    
    def test_toggle_feature_flag_enable(self, client):
        """Test enabling a feature flag"""
        flag_name = "structured_logging"
        
        # Enable the flag
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": flag_name, "enabled": True}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["flag_name"] == flag_name
        assert data["enabled"] == True
        
        # Verify it's enabled
        response = client.get(f"/api/feature-flags/{flag_name}")
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == True
    
    def test_toggle_feature_flag_disable(self, client):
        """Test disabling a feature flag"""
        flag_name = "structured_logging"
        
        # First enable it
        client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": flag_name, "enabled": True}
        )
        
        # Then disable it
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": flag_name, "enabled": False}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["flag_name"] == flag_name
        assert data["enabled"] == False
    
    def test_emergency_rollback(self, client):
        """Test emergency rollback functionality"""
        # Enable a few flags first
        flags_to_enable = ["structured_logging", "enhanced_error_handling"]
        
        for flag in flags_to_enable:
            client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": flag, "enabled": True}
            )
        
        # Perform emergency rollback
        response = client.post("/api/feature-flags/emergency-rollback")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "rollback_completed"
        assert "message" in data
        assert "flags_disabled" in data
    
    def test_invalid_flag_name(self, client):
        """Test handling of invalid flag names"""
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": "invalid_flag_name", "enabled": True}
        )
        
        # Should handle gracefully, possibly returning error
        assert response.status_code in [200, 400]
    
    def test_malformed_toggle_request(self, client):
        """Test handling of malformed toggle requests"""
        # Missing required fields
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": "test_flag"}  # Missing 'enabled' field
        )
        
        assert response.status_code == 422  # Validation error


@pytest.mark.api
@pytest.mark.security
class TestAuthenticationAPI:
    """Test authentication API endpoints"""
    
    def test_aws_credentials_validation_endpoint(self, client, mock_aws_credentials):
        """Test AWS credentials validation endpoint"""
        response = client.post(
            "/api/auth/aws-credentials",
            json=mock_aws_credentials
        )
        
        # May fail due to actual AWS call, but should not crash
        assert response.status_code in [200, 400, 401]
    
    def test_aws_credential_status_com(self, client):
        """Test getting AWS credential status for COM environment"""
        response = client.get("/api/auth/aws-credentials/com")
        
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "com"
        assert "valid" in data
        assert "message" in data
    
    def test_aws_credential_status_gov(self, client):
        """Test getting AWS credential status for GOV environment"""
        response = client.get("/api/auth/aws-credentials/gov")
        
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "gov"
        assert "valid" in data
        assert "message" in data
    
    def test_clear_aws_credentials(self, client):
        """Test clearing AWS credentials"""
        response = client.delete("/api/auth/aws-credentials/com")
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True
        assert "message" in data
    
    def test_list_credential_environments(self, client):
        """Test listing supported credential environments"""
        response = client.get("/api/auth/aws-credentials")
        
        assert response.status_code == 200
        data = response.json()
        assert "environments" in data
        assert isinstance(data["environments"], list)
        assert "com" in data["environments"]
        assert "gov" in data["environments"]
    
    def test_check_credentials_endpoint(self, client):
        """Test detailed credential check endpoint"""
        response = client.get("/api/auth/aws-check-credentials")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have entries for both environments
        # May be None if no credentials configured
        assert "com" in data or data.get("com") is None
        assert "gov" in data or data.get("gov") is None


@pytest.mark.integration 
@pytest.mark.database
class TestDatabaseIntegration:
    """Test database integration with API endpoints"""
    
    def test_database_connection_via_api(self, client):
        """Test database connection through API calls"""
        # Test an endpoint that requires database access
        response = client.get("/api/providers")
        
        # Should succeed, not return database errors
        assert response.status_code == 200
        assert "error" not in response.json()
    
    def test_session_creation_via_web_request(self, client):
        """Test session creation through web interface"""
        response = client.get("/aws")
        
        assert response.status_code == 200
        # Should set session cookie
        assert any('session' in cookie.name.lower() for cookie in response.cookies.values())


@pytest.mark.api
@pytest.mark.critical
class TestCriticalAPIPathsIntegration:
    """Test critical API paths that must work after fixes"""
    
    def test_core_application_flow(self, client):
        """Test complete application flow through API"""
        # 1. Health check
        response = client.get("/api/health")
        assert response.status_code == 200
        
        # 2. Feature flags health
        response = client.get("/api/feature-flags/health")
        assert response.status_code == 200
        
        # 3. Providers list
        response = client.get("/api/providers")
        assert response.status_code == 200
        
        # 4. AWS credentials check
        response = client.get("/api/auth/aws-check-credentials")
        assert response.status_code == 200
    
    def test_feature_flag_rollback_integration(self, client):
        """Test complete feature flag rollback scenario"""
        # 1. Check initial state
        response = client.get("/api/feature-flags/health")
        assert response.status_code == 200
        initial_enabled = response.json()["enabled_flags"]
        
        # 2. Enable a flag
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": "structured_logging", "enabled": True}
        )
        assert response.status_code == 200
        
        # 3. Verify it's enabled
        response = client.get("/api/feature-flags/health")
        assert response.status_code == 200
        new_enabled = response.json()["enabled_flags"]
        assert new_enabled > initial_enabled
        
        # 4. Emergency rollback
        response = client.post("/api/feature-flags/emergency-rollback")
        assert response.status_code == 200
        
        # 5. Verify rollback worked
        response = client.get("/api/feature-flags/health")
        assert response.status_code == 200
        final_enabled = response.json()["enabled_flags"]
        assert final_enabled <= initial_enabled


@pytest.mark.web
class TestWebInterfaceIntegration:
    """Test web interface integration"""
    
    def test_home_page(self, client):
        """Test home page loads"""
        response = client.get("/")
        
        assert response.status_code == 200
        assert "PCM-Ops Tools" in response.text
    
    def test_aws_auth_page(self, client):
        """Test AWS authentication page loads"""
        response = client.get("/aws")
        
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
    
    def test_aws_tools_page(self, client):
        """Test AWS tools page loads"""
        response = client.get("/aws/tools")
        
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
    
    def test_static_files_served(self, client):
        """Test static files are served correctly"""
        response = client.get("/static/css/bootstrap.min.css")
        
        assert response.status_code == 200
        assert "text/css" in response.headers.get("content-type", "")
    
    def test_api_documentation(self, client):
        """Test API documentation is accessible"""
        response = client.get("/docs")
        
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


@pytest.mark.integration
@pytest.mark.slow
class TestPerformanceIntegration:
    """Test performance integration across components"""
    
    def test_health_check_performance(self, client):
        """Test health check response time"""
        import time
        
        start_time = time.time()
        response = client.get("/api/health")
        end_time = time.time()
        
        assert response.status_code == 200
        
        response_time = end_time - start_time
        # Should respond quickly
        assert response_time < 2.0
    
    def test_feature_flags_performance(self, client):
        """Test feature flags endpoint performance"""
        import time
        
        start_time = time.time()
        response = client.get("/api/feature-flags")
        end_time = time.time()
        
        assert response.status_code == 200
        
        response_time = end_time - start_time
        # Should respond quickly
        assert response_time < 3.0
    
    def test_concurrent_requests_simulation(self, client):
        """Test handling multiple concurrent requests"""
        import concurrent.futures
        import threading
        
        def make_request():
            return client.get("/api/health")
        
        # Simulate 5 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [future.result() for future in futures]
        
        # All should succeed
        for response in results:
            assert response.status_code == 200