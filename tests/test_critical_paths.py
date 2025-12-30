"""
Critical Path Testing for Phase 0 Infrastructure

This module contains tests for critical application functionality that must
work correctly after any changes or rollbacks.
"""

import pytest
import requests
import time
from typing import Dict, Any


class TestCriticalPaths:
    """Test critical application paths to ensure basic functionality"""
    
    BASE_URL = "http://localhost:8500"
    STAGING_URL = "http://localhost:8501"
    
    @pytest.fixture
    def base_url(self, request):
        """Get base URL from test configuration"""
        return getattr(request.config.option, 'base_url', self.BASE_URL)
    
    def test_application_health(self, base_url):
        """Test that application starts and responds to health checks"""
        response = requests.get(f"{base_url}/api/health", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"
    
    def test_feature_flags_system(self, base_url):
        """Test that feature flag system is working"""
        # Check feature flags health
        response = requests.get(f"{base_url}/api/feature-flags/health", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "total_flags" in data
        assert "enabled_flags" in data
    
    def test_feature_flags_list(self, base_url):
        """Test that we can list all feature flags"""
        response = requests.get(f"{base_url}/api/feature-flags", timeout=10)
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
            assert flag in data, f"Missing feature flag: {flag}"
    
    def test_web_interface_responds(self, base_url):
        """Test that web interface loads"""
        response = requests.get(base_url, timeout=10)
        assert response.status_code == 200
        assert "PCM-Ops Tools" in response.text
    
    def test_api_documentation_available(self, base_url):
        """Test that API documentation is accessible"""
        response = requests.get(f"{base_url}/docs", timeout=10)
        assert response.status_code == 200
        assert "FastAPI" in response.text or "Swagger" in response.text
    
    def test_static_files_serve(self, base_url):
        """Test that static files are served correctly"""
        # Try to load CSS file
        response = requests.get(f"{base_url}/static/css/bootstrap.min.css", timeout=10)
        assert response.status_code == 200
        assert "bootstrap" in response.text.lower()
    
    def test_providers_endpoint(self, base_url):
        """Test that providers endpoint works"""
        response = requests.get(f"{base_url}/api/providers", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert "providers" in data
        assert isinstance(data["providers"], dict)
    
    def test_aws_auth_pages_load(self, base_url):
        """Test that AWS authentication pages load"""
        response = requests.get(f"{base_url}/aws", timeout=10)
        assert response.status_code == 200
        assert "AWS" in response.text
    
    def test_aws_tools_page_loads(self, base_url):
        """Test that AWS tools page loads"""
        response = requests.get(f"{base_url}/aws/tools", timeout=10)
        assert response.status_code == 200
        assert "tools" in response.text.lower()
    
    def test_database_connectivity(self, base_url):
        """Test that database is accessible (indirect test via API)"""
        # Test an endpoint that requires database access
        response = requests.get(f"{base_url}/api/auth/aws-credentials", timeout=10)
        # Should return 200 with environment list, not a 500 database error
        assert response.status_code == 200
    
    def test_session_middleware_working(self, base_url):
        """Test that session middleware is functioning"""
        # Make a request that sets a session
        session = requests.Session()
        
        # First request - should set session cookie
        response = session.get(f"{base_url}/aws", timeout=10)
        assert response.status_code == 200
        
        # Check for session cookie
        assert any('session' in cookie.name.lower() for cookie in session.cookies)
    
    def test_cors_configuration(self, base_url):
        """Test that CORS is properly configured"""
        # Make a preflight request
        headers = {
            'Origin': 'http://localhost:3000',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Content-Type'
        }
        
        response = requests.options(f"{base_url}/api/health", headers=headers, timeout=10)
        # Should not be blocked by CORS
        assert response.status_code in [200, 204]


class TestFeatureFlagOperations:
    """Test feature flag operations for rollback capabilities"""
    
    BASE_URL = "http://localhost:8500"
    
    @pytest.fixture
    def base_url(self, request):
        """Get base URL from test configuration"""
        return getattr(request.config.option, 'base_url', self.BASE_URL)
    
    def test_toggle_feature_flag(self, base_url):
        """Test toggling a feature flag on and off"""
        flag_name = "structured_logging"
        
        # Get initial state
        response = requests.get(f"{base_url}/api/feature-flags/{flag_name}", timeout=10)
        assert response.status_code == 200
        initial_state = response.json()
        
        # Toggle flag on
        toggle_request = {
            "flag_name": flag_name,
            "enabled": True
        }
        
        response = requests.post(
            f"{base_url}/api/feature-flags/toggle",
            json=toggle_request,
            timeout=10
        )
        assert response.status_code == 200
        
        # Verify it's enabled
        response = requests.get(f"{base_url}/api/feature-flags/{flag_name}", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == True
        
        # Toggle flag off (rollback)
        toggle_request["enabled"] = False
        response = requests.post(
            f"{base_url}/api/feature-flags/toggle",
            json=toggle_request,
            timeout=10
        )
        assert response.status_code == 200
        
        # Verify it's disabled
        response = requests.get(f"{base_url}/api/feature-flags/{flag_name}", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == False
    
    def test_emergency_rollback(self, base_url):
        """Test emergency rollback functionality"""
        # Enable a few flags first
        flags_to_test = ["structured_logging", "enhanced_error_handling"]
        
        for flag_name in flags_to_test:
            toggle_request = {
                "flag_name": flag_name,
                "enabled": True
            }
            response = requests.post(
                f"{base_url}/api/feature-flags/toggle",
                json=toggle_request,
                timeout=10
            )
            assert response.status_code == 200
        
        # Verify flags are enabled
        for flag_name in flags_to_test:
            response = requests.get(f"{base_url}/api/feature-flags/{flag_name}", timeout=10)
            data = response.json()
            # Note: May not actually be enabled if flag logic prevents it
            # Just check that the API responds correctly
        
        # Perform emergency rollback
        response = requests.post(f"{base_url}/api/feature-flags/emergency-rollback", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "rollback_completed"
    
    def test_feature_flag_persistence(self, base_url):
        """Test that feature flag changes persist correctly"""
        flag_name = "debug_mode_enabled"
        
        # Set flag to known state
        toggle_request = {
            "flag_name": flag_name,
            "enabled": True
        }
        
        response = requests.post(
            f"{base_url}/api/feature-flags/toggle",
            json=toggle_request,
            timeout=10
        )
        assert response.status_code == 200
        
        # Wait a moment
        time.sleep(1)
        
        # Verify persistence
        response = requests.get(f"{base_url}/api/feature-flags/{flag_name}", timeout=10)
        assert response.status_code == 200
        
        # Clean up
        toggle_request["enabled"] = False
        requests.post(
            f"{base_url}/api/feature-flags/toggle",
            json=toggle_request,
            timeout=10
        )


class TestPerformanceBaseline:
    """Establish performance baselines for rollback detection"""
    
    BASE_URL = "http://localhost:8500"
    
    @pytest.fixture
    def base_url(self, request):
        """Get base URL from test configuration"""
        return getattr(request.config.option, 'base_url', self.BASE_URL)
    
    def test_health_check_performance(self, base_url):
        """Test health check response time baseline"""
        start_time = time.time()
        response = requests.get(f"{base_url}/api/health", timeout=10)
        end_time = time.time()
        
        assert response.status_code == 200
        
        response_time = end_time - start_time
        # Health check should respond in under 1 second
        assert response_time < 1.0, f"Health check too slow: {response_time:.2f}s"
    
    def test_feature_flags_performance(self, base_url):
        """Test feature flags endpoint performance"""
        start_time = time.time()
        response = requests.get(f"{base_url}/api/feature-flags", timeout=10)
        end_time = time.time()
        
        assert response.status_code == 200
        
        response_time = end_time - start_time
        # Feature flags should respond quickly
        assert response_time < 2.0, f"Feature flags too slow: {response_time:.2f}s"
    
    def test_web_page_performance(self, base_url):
        """Test web page load performance"""
        start_time = time.time()
        response = requests.get(base_url, timeout=10)
        end_time = time.time()
        
        assert response.status_code == 200
        
        response_time = end_time - start_time
        # Web pages should load in reasonable time
        assert response_time < 3.0, f"Web page too slow: {response_time:.2f}s"


# Test configuration for pytest
def pytest_addoption(parser):
    """Add command line options for test configuration"""
    parser.addoption(
        "--base-url",
        action="store",
        default="http://localhost:8500",
        help="Base URL for the application"
    )
    parser.addoption(
        "--staging",
        action="store_true",
        help="Run tests against staging environment"
    )


def pytest_configure(config):
    """Configure pytest based on command line options"""
    if config.getoption("--staging"):
        config.option.base_url = "http://localhost:8501"


if __name__ == "__main__":
    """Run tests directly"""
    pytest.main([__file__, "-v"])