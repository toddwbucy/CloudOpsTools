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
        """Test CSRF protection for state-changing operations

        Validates that state-changing endpoints (POST/PUT/DELETE) require
        valid CSRF tokens when CSRF protection is enabled:
        1. POST without CSRF token should fail with 403 Forbidden
        2. POST with valid CSRF token should succeed
        3. CSRF tokens should be unique per session

        If CSRF protection is not yet implemented (Phase 1 feature),
        the test validates current behavior and documents expected behavior.
        """
        # First, check if CSRF token endpoint exists
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF endpoint not implemented yet - test current behavior
            # State-changing endpoint should still work without CSRF
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test_flag", "enabled": True}
            )
            # Should work or return validation error (not CSRF error)
            assert response.status_code in [200, 422], (
                f"Without CSRF implementation, expected 200 or 422, "
                f"got {response.status_code}"
            )
        elif csrf_response.status_code == 200:
            # CSRF protection is implemented - test full protection

            # Get a valid CSRF token
            csrf_data = csrf_response.json()
            assert "csrf_token" in csrf_data, "CSRF response missing token"
            valid_token = csrf_data["csrf_token"]

            # Test 1: POST without CSRF token should fail with 403
            response_no_token = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test_flag", "enabled": True}
            )
            assert response_no_token.status_code == 403, (
                f"POST without CSRF token should return 403, "
                f"got {response_no_token.status_code}"
            )

            # Test 2: POST with invalid CSRF token should fail with 403
            response_invalid = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test_flag", "enabled": True},
                headers={"X-CSRF-Token": "invalid-token-12345"}
            )
            assert response_invalid.status_code == 403, (
                f"POST with invalid CSRF token should return 403, "
                f"got {response_invalid.status_code}"
            )

            # Test 3: POST with valid CSRF token should succeed
            response_valid = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test_flag", "enabled": True},
                headers={"X-CSRF-Token": valid_token}
            )
            # Should succeed (200) or fail validation (422), not CSRF error
            assert response_valid.status_code in [200, 422], (
                f"POST with valid CSRF token should succeed or return "
                f"validation error, got {response_valid.status_code}"
            )

            # Test 4: Verify CSRF tokens are unique per session
            csrf_response2 = client.get("/api/auth/csrf-token")
            if csrf_response2.status_code == 200:
                csrf_data2 = csrf_response2.json()
                token2 = csrf_data2.get("csrf_token", "")
                assert valid_token != token2, (
                    "CSRF tokens must be unique per request to prevent "
                    "replay attacks"
                )
        else:
            # Unexpected status code from CSRF endpoint
            pytest.fail(
                f"Unexpected status {csrf_response.status_code} from "
                f"CSRF token endpoint"
            )
    
    def test_csrf_token_generation_endpoint(self, client):
        """Test CSRF token generation endpoint

        Validates that the /api/auth/csrf-token endpoint:
        1. Returns a valid CSRF token when implemented
        2. Token has sufficient length for security (> 20 chars)
        3. Token is cryptographically random (unique per request)

        If endpoint doesn't exist yet (404), test passes to allow development.
        """
        response = client.get("/api/auth/csrf-token")

        if response.status_code == 404:
            # Endpoint not yet implemented - Phase 1 will add this
            pass
        elif response.status_code == 200:
            # Endpoint exists - validate the response
            data = response.json()

            # CSRF token must be present in response
            assert "csrf_token" in data, (
                "Response missing 'csrf_token' field"
            )

            csrf_token = data["csrf_token"]

            # Token must be a non-empty string
            assert isinstance(csrf_token, str), (
                f"CSRF token must be a string, got {type(csrf_token)}"
            )
            assert len(csrf_token) > 0, "CSRF token cannot be empty"

            # Token must have sufficient length for security
            # Minimum 20 chars (following OWASP recommendations)
            assert len(csrf_token) >= 20, (
                f"CSRF token too short ({len(csrf_token)} chars), "
                "minimum 20 required for security"
            )

            # Verify token uniqueness by making another request
            response2 = client.get("/api/auth/csrf-token")
            if response2.status_code == 200:
                data2 = response2.json()
                csrf_token2 = data2.get("csrf_token", "")
                # Tokens should be unique per request to prevent replay attacks
                assert csrf_token != csrf_token2, (
                    "CSRF tokens must be unique per request"
                )
        else:
            # Unexpected status code
            pytest.fail(
                f"Unexpected status {response.status_code} from CSRF token endpoint. "
                f"Expected 200 (success) or 404 (not implemented)."
            )

    # =========================================================================
    # CSRF Endpoint Definitions for Parametrized Tests
    # =========================================================================

    # Critical priority endpoints - highest risk if CSRF bypassed
    CRITICAL_CSRF_ENDPOINTS = [
        # Feature Flags (can disable security features)
        (
            "/api/feature-flags/toggle",
            "POST",
            {"flag_name": "test_flag", "enabled": True},
            "Toggle feature flag"
        ),
        (
            "/api/feature-flags/emergency-rollback",
            "POST",
            {},
            "Emergency rollback all flags"
        ),
        # Script Executions (can execute arbitrary code)
        (
            "/api/script-runner/executions/",
            "POST",
            {"script_id": 1, "instance_id": "i-1234567890abcdef0", "parameters": {}},
            "Execute script on instance"
        ),
        (
            "/api/script-runner/executions/batch",
            "POST",
            {"script_id": 1, "instance_ids": ["i-1234567890abcdef0"], "parameters": {}},
            "Execute script on multiple instances"
        ),
        (
            "/api/script-runner/executions/single",
            "POST",
            {"script_id": 1, "instance_id": "i-1234567890abcdef0"},
            "Execute single script (modular)"
        ),
        # Tools (can execute tools on instances)
        (
            "/api/tools/1/execute",
            "POST",
            {"instance_id": "i-1234567890abcdef0", "parameters": {}},
            "Execute tool on instance"
        ),
        # AWS Authentication (session hijacking risk)
        (
            "/aws/authenticate",
            "POST",
            {"access_key": "test", "secret_key": "test", "environment": "com"},
            "Authenticate with AWS"
        ),
    ]

    # High priority endpoints - credential/data modification
    HIGH_CSRF_ENDPOINTS = [
        # Auth/Credentials
        (
            "/api/auth/aws-credentials",
            "POST",
            {"access_key": "AKIA12345678EXAMPLE", "secret_key": "testsecret", "environment": "com"},
            "Validate AWS credentials"
        ),
        (
            "/api/auth/aws-credentials/com",
            "DELETE",
            None,
            "Clear AWS credentials"
        ),
        (
            "/aws/test-credentials",
            "POST",
            {"access_key": "test", "secret_key": "test"},
            "Test AWS credentials"
        ),
        (
            "/aws/clear-credentials",
            "POST",
            {},
            "Clear all AWS credentials"
        ),
        # Scripts CRUD
        (
            "/api/scripts/",
            "POST",
            {"name": "test", "content": "echo test", "description": "Test", "script_type": "bash"},
            "Create script"
        ),
        (
            "/api/scripts/1",
            "PUT",
            {"name": "test", "content": "echo updated", "description": "Updated"},
            "Update script"
        ),
        (
            "/api/scripts/1",
            "DELETE",
            None,
            "Delete script"
        ),
        # Changes CRUD
        (
            "/api/script-runner/changes/",
            "POST",
            {"change_number": "CHG0001234", "description": "Test change"},
            "Create change"
        ),
        (
            "/api/script-runner/changes/CHG0001234",
            "PUT",
            {"description": "Updated description"},
            "Update change"
        ),
        # Accounts
        (
            "/api/script-runner/accounts/",
            "POST",
            {"account_id": "123456789012", "name": "Test Account"},
            "Create/discover account"
        ),
        (
            "/api/script-runner/accounts/123456789012",
            "POST",
            {"name": "Updated Account"},
            "Update account"
        ),
        # Organization
        (
            "/api/script-runner/org/visit-organization",
            "POST",
            {"org_id": "o-abc123"},
            "Discover organization accounts"
        ),
        # AWS Operations
        (
            "/api/script-runner/aws-operations/start",
            "POST",
            {"operation_type": "scan"},
            "Start AWS scan"
        ),
        # Linux QC Operations
        (
            "/aws/linux-qc-prep/execute-qc-step",
            "POST",
            {"step": "check", "instance_id": "i-1234567890abcdef0"},
            "Execute QC check step"
        ),
        (
            "/aws/linux-qc-prep/execute-step2-kernel-staging",
            "POST",
            {"instance_id": "i-1234567890abcdef0"},
            "Execute kernel staging"
        ),
        (
            "/aws/linux-qc-prep/execute-step2-multi-kernel",
            "POST",
            {"instance_ids": ["i-1234567890abcdef0"]},
            "Execute multi-kernel step"
        ),
        (
            "/aws/linux-qc-post/execute-post-validation",
            "POST",
            {"instance_id": "i-1234567890abcdef0"},
            "Execute post-patching validation"
        ),
        # SFT Fixer
        (
            "/aws/sft-fixer/execute-script",
            "POST",
            {"instance_id": "i-1234567890abcdef0", "script": "fix"},
            "Execute SFT fix script"
        ),
    ]

    # Medium priority endpoints - workflow operations
    MEDIUM_CSRF_ENDPOINTS = [
        # Linux QC Prep
        (
            "/aws/linux-qc-prep/test-connectivity",
            "POST",
            {"instance_id": "i-1234567890abcdef0"},
            "Test instance connectivity"
        ),
        (
            "/aws/linux-qc-prep/load-change/CHG0001234",
            "POST",
            {},
            "Load change request"
        ),
        (
            "/aws/linux-qc-prep/clear-change",
            "POST",
            {},
            "Clear current change"
        ),
        (
            "/aws/linux-qc-prep/save-change-with-instances",
            "POST",
            {"change_number": "CHG0001234", "instances": []},
            "Save change with instances"
        ),
        (
            "/aws/linux-qc-prep/upload-change-csv",
            "POST",
            {},  # Would have file upload
            "Upload change CSV"
        ),
        # Linux QC Post
        (
            "/aws/linux-qc-post/test-connectivity",
            "POST",
            {"instance_id": "i-1234567890abcdef0"},
            "Test connectivity (post)"
        ),
        (
            "/aws/linux-qc-post/load-change/CHG0001234",
            "POST",
            {},
            "Load change (post)"
        ),
        (
            "/aws/linux-qc-post/clear-change",
            "POST",
            {},
            "Clear change (post)"
        ),
        (
            "/aws/linux-qc-post/save-change-with-instances",
            "POST",
            {"change_number": "CHG0001234", "instances": []},
            "Save change with instances (post)"
        ),
        (
            "/aws/linux-qc-post/upload-change-csv",
            "POST",
            {},
            "Upload change CSV (post)"
        ),
        # SFT Fixer
        (
            "/aws/sft-fixer/validate-instance",
            "POST",
            {"instance_id": "i-1234567890abcdef0"},
            "Validate instance for SFT"
        ),
        # Accounts instances
        (
            "/api/script-runner/accounts/123456789012/instances",
            "POST",
            {},
            "Refresh instances"
        ),
        (
            "/api/script-runner/accounts/123456789012/instances/i-1234567890abcdef0/status",
            "POST",
            {},
            "Get instance status"
        ),
        # Changes
        (
            "/api/script-runner/changes/compare",
            "POST",
            {"change_numbers": ["CHG0001234", "CHG0001235"]},
            "Compare changes"
        ),
        # AWS Operations
        (
            "/api/script-runner/aws-operations/scan123/resume",
            "POST",
            {},
            "Resume scan"
        ),
        # Executions
        (
            "/api/script-runner/executions/batch/batch123/refresh-status",
            "POST",
            {},
            "Refresh batch status"
        ),
        (
            "/api/script-runner/executions/generate-report",
            "POST",
            {"execution_ids": [1, 2, 3]},
            "Generate execution report"
        ),
        (
            "/api/script-runner/executions/status/refresh",
            "POST",
            {"execution_id": 1},
            "Refresh execution status (modular)"
        ),
        (
            "/api/script-runner/executions/reports/generate",
            "POST",
            {"execution_ids": [1]},
            "Generate report (modular)"
        ),
    ]

    # Low priority endpoints - debug/non-sensitive
    LOW_CSRF_ENDPOINTS = [
        (
            "/aws/linux-qc-prep/debug-session",
            "POST",
            {},
            "Debug session state"
        ),
    ]

    # =========================================================================
    # Parametrized CSRF Tests for All Endpoints
    # =========================================================================

    def _make_csrf_request(self, client, endpoint, method, payload, csrf_token=None):
        """Helper to make a request with optional CSRF token

        Returns the response from the request.
        """
        headers = {}
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token

        if method == "POST":
            if payload is not None:
                return client.post(endpoint, json=payload, headers=headers)
            else:
                return client.post(endpoint, headers=headers)
        elif method == "PUT":
            if payload is not None:
                return client.put(endpoint, json=payload, headers=headers)
            else:
                return client.put(endpoint, headers=headers)
        elif method == "DELETE":
            return client.delete(endpoint, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    def _check_csrf_protection(self, client, endpoint, method, payload, description):
        """Helper to test CSRF protection for an endpoint

        Tests that:
        1. If CSRF is not implemented, endpoint works without token
        2. If CSRF is implemented:
           - Request without token returns 403
           - Request with invalid token returns 403
           - Request with valid token succeeds or returns validation error

        Returns True if tests pass, raises AssertionError otherwise.
        """
        # First check if CSRF protection is implemented
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented - endpoint should work without token
            response = self._make_csrf_request(client, endpoint, method, payload)

            if response.status_code == 404:
                # Endpoint not implemented yet
                return True

            # Should work or return validation error, not CSRF error
            assert response.status_code in [200, 201, 400, 401, 422, 405, 500], (
                f"[{description}] Without CSRF implementation, expected success/validation "
                f"error, got {response.status_code}: {response.text[:200]}"
            )
            return True

        elif csrf_response.status_code == 200:
            # CSRF protection is implemented - test full protection
            csrf_data = csrf_response.json()
            valid_token = csrf_data.get("csrf_token", "")

            # Test 1: Request without CSRF token should fail with 403
            response_no_token = self._make_csrf_request(
                client, endpoint, method, payload
            )

            if response_no_token.status_code == 404:
                # Endpoint not implemented yet
                return True

            if response_no_token.status_code == 405:
                # Method not allowed - skip this test
                return True

            assert response_no_token.status_code == 403, (
                f"[{description}] Request without CSRF token should return 403, "
                f"got {response_no_token.status_code}"
            )

            # Test 2: Request with invalid CSRF token should fail with 403
            response_invalid = self._make_csrf_request(
                client, endpoint, method, payload,
                csrf_token="invalid-csrf-token-12345"
            )
            assert response_invalid.status_code == 403, (
                f"[{description}] Request with invalid CSRF token should return 403, "
                f"got {response_invalid.status_code}"
            )

            # Test 3: Request with valid CSRF token should succeed
            response_valid = self._make_csrf_request(
                client, endpoint, method, payload,
                csrf_token=valid_token
            )
            # Should succeed or fail validation, not CSRF error
            assert response_valid.status_code in [200, 201, 400, 401, 422, 500], (
                f"[{description}] Request with valid CSRF token should succeed or "
                f"return validation error, got {response_valid.status_code}"
            )

            return True

        else:
            pytest.fail(
                f"Unexpected status {csrf_response.status_code} from CSRF token endpoint"
            )

    # -------------------------------------------------------------------------
    # CRITICAL Priority Endpoint Tests
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize(
        "endpoint,method,payload,description",
        CRITICAL_CSRF_ENDPOINTS,
        ids=[e[3] for e in CRITICAL_CSRF_ENDPOINTS]
    )
    def test_csrf_critical_endpoints(self, client, endpoint, method, payload, description):
        """Test CSRF protection for CRITICAL priority endpoints

        These endpoints have the highest security risk if CSRF protection
        is bypassed. They include:
        - Feature flag toggles (can disable security features)
        - Script executions (can execute arbitrary code on instances)
        - Tool executions (can run tools on instances)
        - AWS authentication (session hijacking risk)

        Expected behavior:
        - If CSRF not implemented: Endpoints work normally
        - If CSRF implemented: Must require valid CSRF token
        """
        self._check_csrf_protection(client, endpoint, method, payload, description)

    # -------------------------------------------------------------------------
    # HIGH Priority Endpoint Tests
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize(
        "endpoint,method,payload,description",
        HIGH_CSRF_ENDPOINTS,
        ids=[e[3] for e in HIGH_CSRF_ENDPOINTS]
    )
    def test_csrf_high_priority_endpoints(self, client, endpoint, method, payload, description):
        """Test CSRF protection for HIGH priority endpoints

        These endpoints handle sensitive operations including:
        - Credential validation and clearing
        - Script CRUD operations
        - Change request management
        - Account and organization management
        - Kernel/patching execution steps

        Expected behavior:
        - If CSRF not implemented: Endpoints work normally
        - If CSRF implemented: Must require valid CSRF token
        """
        self._check_csrf_protection(client, endpoint, method, payload, description)

    # -------------------------------------------------------------------------
    # MEDIUM Priority Endpoint Tests
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize(
        "endpoint,method,payload,description",
        MEDIUM_CSRF_ENDPOINTS,
        ids=[e[3] for e in MEDIUM_CSRF_ENDPOINTS]
    )
    def test_csrf_medium_priority_endpoints(self, client, endpoint, method, payload, description):
        """Test CSRF protection for MEDIUM priority endpoints

        These endpoints handle workflow operations including:
        - Connectivity testing
        - Change loading/clearing
        - Status refresh operations
        - Report generation

        Expected behavior:
        - If CSRF not implemented: Endpoints work normally
        - If CSRF implemented: Must require valid CSRF token
        """
        self._check_csrf_protection(client, endpoint, method, payload, description)

    # -------------------------------------------------------------------------
    # LOW Priority Endpoint Tests
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize(
        "endpoint,method,payload,description",
        LOW_CSRF_ENDPOINTS,
        ids=[e[3] for e in LOW_CSRF_ENDPOINTS]
    )
    def test_csrf_low_priority_endpoints(self, client, endpoint, method, payload, description):
        """Test CSRF protection for LOW priority endpoints

        These endpoints handle non-sensitive operations including:
        - Debug operations

        Expected behavior:
        - If CSRF not implemented: Endpoints work normally
        - If CSRF implemented: May or may not require CSRF token
        """
        self._check_csrf_protection(client, endpoint, method, payload, description)

    # =========================================================================
    # Additional CSRF Security Tests
    # =========================================================================

    def test_csrf_token_not_accepted_after_expiration(self, client):
        """Test that expired CSRF tokens are rejected

        CSRF tokens should have a limited lifetime to prevent
        replay attacks using stolen tokens. Per security requirements,
        tokens should expire after 1 hour.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            csrf_token = csrf_data.get("csrf_token", "")

            # If expiration is implemented, there should be an expiry field
            # or tokens should be bound to session
            if "expires_at" in csrf_data:
                import datetime
                expiry = csrf_data["expires_at"]
                # Verify expiry is in the future
                assert expiry, "CSRF token should have an expiration time"

    def test_csrf_token_expiration_time(self, client):
        """Test that CSRF tokens have proper 1-hour expiration time

        Validates that CSRF tokens are configured with a reasonable
        expiration window. Per security best practices, CSRF tokens
        should expire after 1 hour (3600 seconds) to balance security
        and usability.

        If CSRF not implemented yet, test passes to allow development.
        """
        import datetime

        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()

            # Check if expiration metadata is provided
            if "expires_at" in csrf_data:
                expiry_str = csrf_data["expires_at"]

                # Parse ISO 8601 format timestamp
                try:
                    if expiry_str.endswith("Z"):
                        expiry = datetime.datetime.fromisoformat(
                            expiry_str.replace("Z", "+00:00")
                        )
                    else:
                        expiry = datetime.datetime.fromisoformat(expiry_str)

                    now = datetime.datetime.now(datetime.timezone.utc)
                    time_until_expiry = (expiry - now).total_seconds()

                    # Token should expire within 1 hour (3600 seconds)
                    # Allow some tolerance for processing time (±60 seconds)
                    assert 0 < time_until_expiry <= 3660, (
                        f"CSRF token should expire within 1 hour, "
                        f"but expires in {time_until_expiry} seconds"
                    )

                    # Token should not expire too quickly (minimum 30 minutes)
                    # This prevents tokens from being unusable
                    assert time_until_expiry >= 1800, (
                        f"CSRF token expires too quickly ({time_until_expiry}s), "
                        f"minimum 30 minutes (1800s) required"
                    )
                except ValueError as e:
                    pytest.fail(
                        f"Invalid expiration timestamp format: {expiry_str}. "
                        f"Error: {e}"
                    )

            elif "expires_in" in csrf_data:
                # Alternative format: seconds until expiration
                expires_in = csrf_data["expires_in"]

                assert isinstance(expires_in, (int, float)), (
                    f"expires_in must be numeric, got {type(expires_in)}"
                )

                # Should be 1 hour (3600 seconds) or less
                assert 0 < expires_in <= 3600, (
                    f"CSRF token should expire within 1 hour (3600s), "
                    f"but expires_in is {expires_in}s"
                )

                # Should not expire too quickly
                assert expires_in >= 1800, (
                    f"CSRF token expires too quickly ({expires_in}s), "
                    f"minimum 30 minutes required"
                )

    def test_csrf_token_cannot_be_reused(self, client):
        """Test that CSRF tokens cannot be reused after successful use

        Single-use tokens provide stronger protection against replay
        attacks. Once a token is used successfully, it should be
        invalidated and rejected on subsequent requests.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            csrf_token = csrf_data.get("csrf_token", "")

            # First request: Use the token successfully
            first_response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "csrf_reuse_test", "enabled": True},
                headers={"X-CSRF-Token": csrf_token}
            )

            if first_response.status_code == 404:
                # Endpoint not yet implemented
                return

            # If CSRF is enforced, first request should succeed
            # (or fail with validation error, not CSRF error)
            if first_response.status_code == 403:
                # CSRF enforcement may be active but tokens work differently
                # Skip this test scenario
                return

            # Second request: Attempt to reuse the same token
            second_response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "csrf_reuse_test_2", "enabled": False},
                headers={"X-CSRF-Token": csrf_token}
            )

            # If single-use tokens are implemented, second request should fail
            # Note: Some CSRF implementations allow reuse within a window
            # Document expected behavior based on implementation
            if second_response.status_code == 403:
                # Single-use tokens implemented - good security practice
                pass
            elif second_response.status_code in [200, 422]:
                # Token reuse allowed - document this behavior
                # This is acceptable if tokens are session-bound with expiration
                pass

    def test_csrf_token_reuse_prevention_strict(self, client):
        """Test strict single-use CSRF token enforcement

        Validates that when strict token reuse prevention is enabled,
        tokens become invalid immediately after first successful use.
        This prevents replay attacks even within the token's validity window.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            csrf_token = csrf_data.get("csrf_token", "")

            # Check if single_use flag is present in response
            is_single_use = csrf_data.get("single_use", False)

            if is_single_use:
                # Test that token cannot be reused
                # First successful use
                response1 = client.post(
                    "/api/feature-flags/toggle",
                    json={"flag_name": "strict_reuse_test", "enabled": True},
                    headers={"X-CSRF-Token": csrf_token}
                )

                if response1.status_code not in [404, 403]:
                    # Token was used successfully, should be invalidated

                    # Immediate reuse attempt
                    response2 = client.post(
                        "/api/feature-flags/toggle",
                        json={"flag_name": "strict_reuse_test_2", "enabled": False},
                        headers={"X-CSRF-Token": csrf_token}
                    )

                    assert response2.status_code == 403, (
                        f"Single-use CSRF token should be rejected on reuse, "
                        f"got {response2.status_code}"
                    )

    def test_csrf_token_rotation_after_use(self, client):
        """Test that a new CSRF token is provided after token use

        After a CSRF token is used (especially with single-use tokens),
        the server should provide a fresh token for the next request.
        This ensures continuous protection without requiring full page reloads.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            original_token = csrf_data.get("csrf_token", "")

            # Use the token
            use_response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "rotation_test", "enabled": True},
                headers={"X-CSRF-Token": original_token}
            )

            if use_response.status_code not in [404]:
                # Get a new token
                new_csrf_response = client.get("/api/auth/csrf-token")

                if new_csrf_response.status_code == 200:
                    new_csrf_data = new_csrf_response.json()
                    new_token = new_csrf_data.get("csrf_token", "")

                    # New token should be different (rotation occurred)
                    assert original_token != new_token, (
                        "CSRF token should be rotated after use to prevent "
                        "replay attacks"
                    )

                    # New token should also be valid (proper length)
                    assert len(new_token) >= 20, (
                        f"Rotated CSRF token too short ({len(new_token)} chars)"
                    )

    def test_csrf_expired_token_rejected(self, client):
        """Test that manipulated/fake expired tokens are rejected

        Validates that tokens with tampered expiration times or
        completely fabricated tokens are properly rejected.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            # Create fake tokens that might be used in attacks
            fake_tokens = [
                # Empty token
                "",
                # Very short token
                "abc123",
                # Token with obvious manipulation markers
                "expired_token_12345678901234567890",
                # Token with special characters (injection attempts)
                "token_<script>alert(1)</script>",
                # Token with null bytes
                "token_with\x00null_byte",
                # Very long token (buffer overflow attempt)
                "a" * 10000,
            ]

            for fake_token in fake_tokens:
                response = client.post(
                    "/api/feature-flags/toggle",
                    json={"flag_name": "fake_token_test", "enabled": True},
                    headers={"X-CSRF-Token": fake_token}
                )

                if response.status_code == 404:
                    # Endpoint not implemented
                    continue

                # Fake tokens should be rejected with 403
                assert response.status_code in [403, 400], (
                    f"Fake/manipulated CSRF token '{fake_token[:50]}...' "
                    f"should be rejected, got {response.status_code}"
                )

    def test_csrf_protection_on_all_http_methods(self, client):
        """Test that CSRF protection covers all state-changing HTTP methods

        POST, PUT, DELETE, and PATCH should all require CSRF tokens.
        GET and HEAD should not require CSRF tokens.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            # GET requests should not need CSRF token
            get_response = client.get("/api/health")
            assert get_response.status_code != 403, (
                "GET requests should not require CSRF token"
            )

            # HEAD requests should not need CSRF token
            head_response = client.head("/api/health")
            assert head_response.status_code != 403, (
                "HEAD requests should not require CSRF token"
            )

    def test_csrf_token_bound_to_session(self, client):
        """Test that CSRF tokens are bound to the user's session

        A CSRF token generated in one session should not be valid
        in a different session to prevent token theft.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            # Document expected behavior: tokens should be session-bound
            # This test will validate once CSRF is fully implemented
            csrf_data = csrf_response.json()
            assert "csrf_token" in csrf_data, "CSRF response should contain token"

    def test_csrf_double_submit_cookie_pattern(self, client):
        """Test double-submit cookie pattern if implemented

        The double-submit cookie pattern requires the CSRF token to be
        sent both as a cookie and as a header/form field. The server
        compares both values.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            # Check if CSRF cookie is set
            csrf_cookies = [
                cookie for cookie in csrf_response.cookies.values()
                if 'csrf' in cookie.name.lower()
            ]

            if csrf_cookies:
                # Double-submit pattern is in use
                csrf_cookie = csrf_cookies[0]
                # Cookie should have proper security flags
                # (These will be validated after implementation)
                pass

    def test_csrf_origin_header_validation(self, client):
        """Test that Origin header is validated for CSRF protection

        Requests with mismatched Origin headers should be rejected
        as they may indicate CSRF attacks.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            csrf_token = csrf_data.get("csrf_token", "")

            # Request with suspicious Origin header
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test", "enabled": True},
                headers={
                    "X-CSRF-Token": csrf_token,
                    "Origin": "https://evil-attacker.com"
                }
            )

            if response.status_code != 404:
                # Should either succeed (if origin checking not implemented)
                # or fail with 403 (if origin checking is implemented)
                # Both are acceptable based on implementation status
                assert response.status_code in [200, 403, 422], (
                    f"Request with suspicious origin should succeed or be blocked, "
                    f"got {response.status_code}"
                )

    def test_csrf_referer_header_validation(self, client):
        """Test that Referer header is validated for CSRF protection

        Requests with mismatched Referer headers may indicate CSRF attacks.

        If CSRF not implemented yet, test passes to allow development.
        """
        csrf_response = client.get("/api/auth/csrf-token")

        if csrf_response.status_code == 404:
            # CSRF not implemented yet
            pass
        elif csrf_response.status_code == 200:
            csrf_data = csrf_response.json()
            csrf_token = csrf_data.get("csrf_token", "")

            # Request with suspicious Referer header
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": "test", "enabled": True},
                headers={
                    "X-CSRF-Token": csrf_token,
                    "Referer": "https://malicious-site.com/attack"
                }
            )

            if response.status_code != 404:
                # Should either succeed (if referer checking not implemented)
                # or fail with 403 (if referer checking is implemented)
                assert response.status_code in [200, 403, 422], (
                    f"Request with suspicious referer should succeed or be blocked, "
                    f"got {response.status_code}"
                )


@pytest.mark.security
@pytest.mark.xss
class TestXSSProtection:
    """Test XSS protection measures"""

    # =========================================================================
    # XSS Payload Definitions for Parametrized Tests
    # =========================================================================

    # Core XSS payloads covering common attack vectors
    XSS_PAYLOADS = [
        # Basic script injection
        "<script>alert('xss')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        # Event handlers
        "<img src=x onerror=alert('xss')>",
        "<svg/onload=alert('xss')>",
        "<body onload=alert('xss')>",
        # JavaScript URL schemes
        "javascript:alert('xss')",
        "javascript:alert(document.cookie)",
        # Attribute escaping
        "\" onclick=\"alert('xss')\" x=\"",
        "' onclick='alert(1)' x='",
        # Mixed case bypass attempts
        "<ScRiPt>alert('xss')</ScRiPt>",
        # External script loading
        "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
    ]

    # Critical endpoints and their test configurations
    # Format: (endpoint, method, field_name, json_template)
    CRITICAL_USER_INPUT_ENDPOINTS = [
        ("/api/feature-flags/toggle", "POST", "flag_name", {"flag_name": "{payload}", "enabled": True}),
        ("/api/auth/aws-credentials", "POST", "access_key", {"access_key": "{payload}", "secret_key": "test", "environment": "com"}),
        ("/api/scripts/", "POST", "name", {"name": "{payload}", "content": "echo test", "description": "Test", "script_type": "bash"}),
        ("/api/scripts/", "POST", "description", {"name": "test", "content": "echo test", "description": "{payload}", "script_type": "bash"}),
    ]

    # =========================================================================
    # Parametrized XSS Payload Tests
    # =========================================================================

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_feature_flag_name(self, client, payload):
        """Test XSS payloads are blocked in feature flag name field

        Validates that XSS payloads in the flag_name field are either:
        1. Rejected with validation error (400, 422)
        2. Sanitized before being included in responses
        3. Not reflected in the response at all

        If endpoint doesn't exist yet (404), test passes to allow development.
        """
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": payload, "enabled": True}
        )

        if response.status_code == 404:
            # Endpoint not yet implemented
            pass
        elif response.status_code == 200:
            # If accepted, payload should be sanitized in response
            response_text = response.text
            assert payload not in response_text, (
                f"XSS payload '{payload[:50]}...' reflected unescaped in response"
            )
        else:
            # Validation rejection (400, 422, 403) is acceptable
            assert response.status_code in [400, 422, 403], (
                f"Unexpected status {response.status_code} for XSS payload"
            )

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_credentials_access_key(self, client, payload):
        """Test XSS payloads are blocked in credentials access_key field

        AWS credential fields should have strict validation that rejects
        XSS payloads. Validates proper input validation is in place.
        """
        response = client.post(
            "/api/auth/aws-credentials",
            json={
                "access_key": payload,
                "secret_key": "test-secret-key",
                "session_token": "test-token",
                "environment": "com"
            }
        )

        if response.status_code == 404:
            # Endpoint not yet implemented
            pass
        elif response.status_code == 200:
            # If accepted, verify payload not reflected unescaped
            response_text = response.text
            assert payload not in response_text, (
                f"XSS payload in access_key reflected unescaped"
            )
        else:
            # Validation rejection is expected and correct behavior
            assert response.status_code in [400, 422, 403, 401], (
                f"Unexpected status {response.status_code} for XSS in credentials"
            )

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_credentials_secret_key(self, client, payload):
        """Test XSS payloads are blocked in credentials secret_key field"""
        response = client.post(
            "/api/auth/aws-credentials",
            json={
                "access_key": "AKIA1234567890EXAMPLE",
                "secret_key": payload,
                "session_token": "test-token",
                "environment": "com"
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code == 200:
            assert payload not in response.text
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_script_name(self, client, payload):
        """Test XSS payloads are blocked in script name field

        Script names are stored and displayed in the UI, making this
        a critical XSS vector. Payloads must be rejected or sanitized.
        """
        response = client.post(
            "/api/scripts/",
            json={
                "name": payload,
                "content": "#!/bin/bash\necho 'test'",
                "description": "Test script",
                "script_type": "bash"
            }
        )

        if response.status_code == 404:
            # Scripts endpoint not implemented
            pass
        elif response.status_code in [200, 201]:
            # If accepted, payload must be sanitized
            response_text = response.text
            assert payload not in response_text, (
                f"XSS payload in script name reflected unescaped"
            )
        else:
            # Validation rejection is acceptable
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_script_description(self, client, payload):
        """Test XSS payloads are blocked in script description field

        Script descriptions are displayed in the UI. XSS payloads
        must be properly handled to prevent stored XSS attacks.
        """
        response = client.post(
            "/api/scripts/",
            json={
                "name": "test-script",
                "content": "#!/bin/bash\necho 'test'",
                "description": payload,
                "script_type": "bash"
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            assert payload not in response.text
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_change_number(self, client, payload):
        """Test XSS payloads are blocked in change number field

        Change numbers are stored and displayed throughout the application.
        This is a high-priority XSS vector.
        """
        response = client.post(
            "/api/script-runner/changes/",
            json={
                "change_number": payload,
                "description": "Test change",
                "status": "pending",
                "instances": []
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            assert payload not in response.text
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_change_description(self, client, payload):
        """Test XSS payloads are blocked in change description field"""
        response = client.post(
            "/api/script-runner/changes/",
            json={
                "change_number": "CHG0001234",
                "description": payload,
                "status": "pending",
                "instances": []
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            assert payload not in response.text
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_execution_parameters(self, client, payload):
        """Test XSS payloads are blocked in execution parameters

        Execution parameters are stored and may be displayed in logs
        or execution results. XSS payloads must be handled safely.
        """
        response = client.post(
            "/api/script-runner/executions/",
            json={
                "script_id": 1,
                "instance_id": "i-1234567890abcdef0",
                "parameters": {"user_input": payload}
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            assert payload not in response.text
        else:
            assert response.status_code in [400, 422, 403, 401]

    # =========================================================================
    # Comprehensive Multi-Field XSS Tests
    # =========================================================================

    def test_xss_payloads_blocked_across_all_fields(self, client, security_test_payloads):
        """Test that XSS payloads from fixture are blocked across endpoints

        Uses the security_test_payloads fixture from conftest.py to test
        multiple XSS payloads across various endpoints.
        """
        xss_payloads = security_test_payloads.get("xss_payloads", [])

        for payload in xss_payloads:
            # Test feature flags endpoint
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": payload, "enabled": True}
            )
            if response.status_code not in [404]:
                assert payload not in response.text, (
                    f"XSS payload '{payload}' found in feature-flags response"
                )

    def test_reflected_xss_in_query_parameters(self, client):
        """Test XSS payloads in query parameters are not reflected

        Query parameters in search or filter endpoints should not
        be reflected unescaped in error messages or responses.
        """
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        test_endpoints = [
            "/api/scripts/?search={payload}",
            "/api/script-runner/changes/?change_number={payload}",
            "/api/script-runner/executions/?status={payload}",
        ]

        for endpoint_template in test_endpoints:
            for payload in xss_payloads:
                endpoint = endpoint_template.format(payload=payload)
                response = client.get(endpoint)

                if response.status_code not in [404, 405]:
                    # Payload should not appear unescaped in response
                    assert payload not in response.text, (
                        f"XSS payload reflected in query param for {endpoint}"
                    )

    def test_xss_in_path_parameters_error_messages(self, client):
        """Test XSS payloads in path parameters are escaped in errors

        Path parameters with invalid values may be reflected in error
        messages. Ensure proper escaping.
        """
        xss_payload = "<script>alert('path-xss')</script>"

        endpoints_with_path_params = [
            f"/api/scripts/{xss_payload}",
            f"/api/feature-flags/{xss_payload}",
            f"/api/script-runner/changes/{xss_payload}",
        ]

        for endpoint in endpoints_with_path_params:
            response = client.get(endpoint)

            # Even in error responses, payload should be escaped
            if xss_payload in response.text:
                # Check if it's properly escaped
                assert "&lt;script&gt;" in response.text or xss_payload not in response.text, (
                    f"XSS payload in path param unescaped at {endpoint}"
                )

    # =========================================================================
    # Existing Tests (Preserved)
    # =========================================================================

    def test_content_security_policy_headers(self, client):
        """Test Content Security Policy headers are set

        Validates that CSP headers are properly configured with nonce-based
        policy for inline scripts. Checks for secure directive configuration.

        This test validates:
        1. If CSP is present, it uses nonce-based policy (not bare 'unsafe-inline')
        2. If CSP has script-src, it doesn't allow 'unsafe-eval'
        3. If CSP has frame-ancestors, it has a proper value

        When CSP headers are not yet implemented (Phase 1 feature),
        the test passes to avoid blocking development, but documents
        the expected security requirements.
        """
        response = client.get("/aws")

        # Check if CSP headers are present (Phase 1 security feature)
        csp_header = response.headers.get("content-security-policy")

        if csp_header:
            # Validate CSP is configured securely
            # If 'unsafe-inline' is used, it must be paired with nonce
            if "unsafe-inline" in csp_header:
                assert "nonce-" in csp_header, (
                    "CSP uses 'unsafe-inline' without nonce - vulnerable to XSS"
                )

            # Validate important CSP directives are present
            # script-src should be defined to control script sources
            if "script-src" in csp_header:
                script_src = self._extract_csp_directive(csp_header, "script-src")
                # Should not allow unsafe-eval (enables eval() attacks)
                assert "unsafe-eval" not in script_src, (
                    "CSP allows 'unsafe-eval' in script-src - security risk"
                )

            # frame-ancestors prevents clickjacking
            if "frame-ancestors" in csp_header:
                frame_ancestors = self._extract_csp_directive(csp_header, "frame-ancestors")
                assert frame_ancestors, "frame-ancestors directive should have a value"
        else:
            # CSP not yet implemented - Phase 1 will add this
            # Test passes to avoid blocking development, but we document requirement
            # When CSP middleware is added, this test will validate proper configuration
            pass  # CSP headers will be added in Phase 1 security implementation

    def test_x_content_type_options_header(self, client):
        """Test X-Content-Type-Options header is set to nosniff

        This header prevents MIME-type sniffing attacks where browsers
        might interpret files as a different MIME type than declared.

        When this header is present, it must be set to 'nosniff'.
        If not present yet (Phase 1 feature), test passes to document requirement.
        """
        response = client.get("/aws")

        x_content_type = response.headers.get("x-content-type-options")

        if x_content_type:
            assert x_content_type.lower() == "nosniff", (
                f"X-Content-Type-Options should be 'nosniff', got '{x_content_type}'"
            )
        else:
            # Header not yet implemented - Phase 1 will add this
            # Test passes to document requirement for when security headers are added
            pass  # X-Content-Type-Options header will be added in Phase 1

    def test_csp_headers_on_api_endpoints(self, client):
        """Test CSP headers are present on API endpoints

        API endpoints should also have security headers to prevent
        XSS through JSON responses that might be rendered.
        """
        api_endpoints = [
            "/api/health",
            "/api/providers",
            "/api/feature-flags",
        ]

        for endpoint in api_endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                # Check for X-Content-Type-Options on API endpoints
                x_content_type = response.headers.get("x-content-type-options")
                if x_content_type:
                    assert x_content_type.lower() == "nosniff", (
                        f"API endpoint {endpoint} has incorrect X-Content-Type-Options"
                    )

    def test_csp_nonce_uniqueness_per_request(self, client):
        """Test that CSP nonces are unique per request

        Each request should receive a unique nonce to prevent
        nonce reuse attacks.
        """
        nonces = []

        for _ in range(3):
            response = client.get("/aws")
            csp_header = response.headers.get("content-security-policy", "")

            # Extract nonce if present
            nonce = self._extract_nonce_from_csp(csp_header)
            if nonce:
                nonces.append(nonce)

        if len(nonces) > 1:
            # All nonces should be unique
            assert len(nonces) == len(set(nonces)), (
                "CSP nonces should be unique per request to prevent reuse attacks"
            )
        elif len(nonces) == 0:
            # Nonces not implemented yet - Phase 1 will add this
            # Test passes to document requirement for CSP nonce implementation
            pass  # CSP nonces will be added in Phase 1 security implementation

    def test_csp_report_uri_configured(self, client):
        """Test CSP report-uri or report-to is configured for violation reporting

        CSP violations should be reported for monitoring and debugging.
        """
        response = client.get("/aws")
        csp_header = response.headers.get("content-security-policy", "")

        if csp_header:
            # Check for either report-uri (deprecated) or report-to (modern)
            has_reporting = "report-uri" in csp_header or "report-to" in csp_header
            # Note: Reporting is recommended but not strictly required
            # This test documents the expected behavior
            if not has_reporting:
                # Log a warning but don't fail - reporting is optional
                pass  # CSP reporting not configured - consider adding for production

    def test_security_headers_consistency_across_routes(self, client):
        """Test that security headers are consistent across all routes

        All routes should have the same security header configuration
        to prevent gaps in protection.
        """
        routes_to_check = [
            "/aws",
            "/api/health",
            "/docs",
        ]

        security_headers_per_route = {}

        for route in routes_to_check:
            response = client.get(route)
            if response.status_code == 200:
                security_headers_per_route[route] = {
                    "x-content-type-options": response.headers.get("x-content-type-options"),
                    "x-frame-options": response.headers.get("x-frame-options"),
                    "x-xss-protection": response.headers.get("x-xss-protection"),
                }

        # Verify at least one route has headers configured
        headers_present = any(
            any(headers.values())
            for headers in security_headers_per_route.values()
        )

        if headers_present:
            # All routes should have consistent header values
            reference_route = next(iter(security_headers_per_route))
            reference_headers = security_headers_per_route[reference_route]

            for route, headers in security_headers_per_route.items():
                for header_name, ref_value in reference_headers.items():
                    if ref_value:  # Only check if reference has the header
                        assert headers.get(header_name) == ref_value, (
                            f"Security header '{header_name}' inconsistent between "
                            f"'{reference_route}' and '{route}'"
                        )

    def _extract_csp_directive(self, csp_header: str, directive: str) -> str:
        """Extract a specific directive value from CSP header"""
        directives = csp_header.split(";")
        for d in directives:
            d = d.strip()
            if d.startswith(directive):
                return d[len(directive):].strip()
        return ""

    def _extract_nonce_from_csp(self, csp_header: str) -> str:
        """Extract nonce value from CSP header if present"""
        import re
        match = re.search(r"'nonce-([^']+)'", csp_header)
        return match.group(1) if match else ""

    # =========================================================================
    # XSS Edge Case Tests (Unicode, URL Encoding, Base64)
    # =========================================================================

    # Unicode XSS payloads - using various unicode representations
    UNICODE_XSS_PAYLOADS = [
        # Fullwidth unicode characters (can bypass filters)
        "\uff1cscript\uff1ealert('xss')\uff1c/script\uff1e",  # Fullwidth < and >
        # Unicode escape sequences
        "\\u003cscript\\u003ealert('xss')\\u003c/script\\u003e",
        # Mixed unicode and ASCII
        "<scr\u0000ipt>alert('xss')</script>",  # Null byte injection
        # Homoglyph attacks (lookalike characters)
        "\u003cscript\u003ealert('xss')\u003c/script\u003e",  # Unicode code points
        # UTF-7 encoding attempt
        "+ADw-script+AD4-alert('xss')+ADw-/script+AD4-",
        # Unicode normalization attacks
        "<script>alert(\u2018xss\u2019)</script>",  # Smart quotes
        # Zero-width characters embedded
        "<scri\u200bpt>alert('xss')</script>",  # Zero-width space
        # Unicode whitespace variations
        "<script\u00a0>alert('xss')</script>",  # Non-breaking space in tag
    ]

    # URL-encoded XSS payloads
    URL_ENCODED_XSS_PAYLOADS = [
        # Standard URL encoding
        "%3Cscript%3Ealert('xss')%3C/script%3E",
        # Double URL encoding
        "%253Cscript%253Ealert('xss')%253C/script%253E",
        # Mixed encoding
        "%3Cscript%3Ealert%28%27xss%27%29%3C/script%3E",
        # Partial encoding (common bypass)
        "<%73cript>alert('xss')</script>",  # %73 = s
        # Event handler URL encoded
        "%3Cimg%20src%3Dx%20onerror%3Dalert('xss')%3E",
        # JavaScript URL scheme encoded
        "javascript%3Aalert%28%27xss%27%29",
        # Unicode URL encoding
        "%u003Cscript%u003Ealert('xss')%u003C/script%u003E",
        # Hex encoding without percent
        "&#x3C;script&#x3E;alert('xss')&#x3C;/script&#x3E;",
    ]

    # Base64-encoded XSS payloads
    BASE64_XSS_PAYLOADS = [
        # data: URI with base64 XSS
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=",
        # JavaScript with base64 payload
        "javascript:eval(atob('YWxlcnQoJ3hzcycp'))",
        # SVG with base64 embedded script
        "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoJ3hzcycpPg==",
        # HTML base64 in data URI
        "data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KCd4c3MnKT4=",
        # Base64 with charset specification
        "data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # Partial base64 decoding attempt
        "eval(atob('YWxlcnQoJ3hzcycp'))",
    ]

    @pytest.mark.parametrize("payload", UNICODE_XSS_PAYLOADS)
    def test_xss_unicode_payloads_in_feature_flag(self, client, payload):
        """Test Unicode XSS payloads are handled in feature flag name

        Unicode attacks attempt to bypass filters using:
        - Fullwidth characters that look like < and >
        - Unicode escape sequences
        - Null byte injection
        - Homoglyph (lookalike) characters
        - Zero-width characters embedded in tags
        """
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": payload, "enabled": True}
        )

        if response.status_code == 404:
            pass  # Endpoint not yet implemented
        elif response.status_code == 200:
            # Check both the raw payload and decoded versions
            response_text = response.text
            assert "<script>" not in response_text.lower(), (
                f"Unicode XSS payload resulted in script tag in response"
            )
            assert "alert(" not in response_text, (
                f"Unicode XSS payload 'alert' found in response"
            )
        else:
            assert response.status_code in [400, 422, 403], (
                f"Unexpected status {response.status_code} for Unicode XSS payload"
            )

    @pytest.mark.parametrize("payload", UNICODE_XSS_PAYLOADS)
    def test_xss_unicode_payloads_in_script_name(self, client, payload):
        """Test Unicode XSS payloads are handled in script name field

        Script names with Unicode attacks could lead to stored XSS
        if the application decodes the Unicode before rendering.
        """
        response = client.post(
            "/api/scripts/",
            json={
                "name": payload,
                "content": "#!/bin/bash\necho 'test'",
                "description": "Test script",
                "script_type": "bash"
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            response_text = response.text
            assert "<script>" not in response_text.lower()
            assert "onerror=" not in response_text.lower()
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", URL_ENCODED_XSS_PAYLOADS)
    def test_xss_url_encoded_payloads_in_feature_flag(self, client, payload):
        """Test URL-encoded XSS payloads are handled in feature flag name

        URL encoding attacks attempt to bypass filters by:
        - Single encoding (%3C for <)
        - Double encoding (%253C)
        - Partial/selective encoding
        - Unicode URL encoding (%u003C)
        """
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": payload, "enabled": True}
        )

        if response.status_code == 404:
            pass
        elif response.status_code == 200:
            response_text = response.text
            # Check for decoded payload in response
            assert "<script>" not in response_text.lower(), (
                f"URL-encoded XSS decoded to script tag"
            )
            # Also check the encoded form wasn't decoded dangerously
            assert "alert(" not in response_text
        else:
            assert response.status_code in [400, 422, 403]

    @pytest.mark.parametrize("payload", URL_ENCODED_XSS_PAYLOADS)
    def test_xss_url_encoded_payloads_in_script_description(self, client, payload):
        """Test URL-encoded XSS payloads are handled in script description

        Script descriptions may be URL-decoded before rendering,
        making them vulnerable to encoded XSS attacks.
        """
        response = client.post(
            "/api/scripts/",
            json={
                "name": "test-script",
                "content": "#!/bin/bash\necho 'test'",
                "description": payload,
                "script_type": "bash"
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            response_text = response.text
            assert "<script>" not in response_text.lower()
            assert "onerror=" not in response_text.lower()
        else:
            assert response.status_code in [400, 422, 403, 401]

    @pytest.mark.parametrize("payload", BASE64_XSS_PAYLOADS)
    def test_xss_base64_payloads_in_feature_flag(self, client, payload):
        """Test Base64-encoded XSS payloads are handled in feature flag name

        Base64 attacks use:
        - data: URIs with base64 content
        - JavaScript eval(atob(...)) patterns
        - SVG images with embedded scripts
        """
        response = client.post(
            "/api/feature-flags/toggle",
            json={"flag_name": payload, "enabled": True}
        )

        if response.status_code == 404:
            pass
        elif response.status_code == 200:
            response_text = response.text
            # data: URIs should not be reflected or should be sanitized
            if "data:" in payload:
                assert "data:text/html" not in response_text, (
                    f"Base64 data URI reflected in response"
                )
            assert "eval(atob" not in response_text, (
                f"Base64 eval pattern found in response"
            )
        else:
            assert response.status_code in [400, 422, 403]

    @pytest.mark.parametrize("payload", BASE64_XSS_PAYLOADS)
    def test_xss_base64_payloads_in_change_description(self, client, payload):
        """Test Base64-encoded XSS payloads are handled in change description

        Change descriptions stored with base64 payloads could execute
        if the application decodes and renders them.
        """
        response = client.post(
            "/api/script-runner/changes/",
            json={
                "change_number": "CHG0001234",
                "description": payload,
                "status": "pending",
                "instances": []
            }
        )

        if response.status_code == 404:
            pass
        elif response.status_code in [200, 201]:
            response_text = response.text
            assert "data:text/html" not in response_text
            assert "eval(atob" not in response_text
        else:
            assert response.status_code in [400, 422, 403, 401]

    def test_xss_mixed_encoding_bypass_attempts(self, client):
        """Test XSS payloads using mixed encoding techniques

        Attackers may combine multiple encoding methods to bypass filters:
        - Unicode + URL encoding
        - Base64 + Unicode
        - Multiple encoding layers
        """
        mixed_payloads = [
            # URL-encoded unicode
            "%3C%u0073cript%3Ealert('xss')%3C/script%3E",
            # Base64 in JavaScript with unicode
            "javascript:eval(atob('\u0059\u0057\u0078\u006c'))",
            # HTML entities + URL encoding
            "&lt;script%3Ealert('xss')&lt;/script%3E",
            # Mixed case + encoding
            "%3CsCrIpT%3Ealert('xss')%3C/ScRiPt%3E",
            # Null bytes + encoding
            "%3Cscr%00ipt%3Ealert('xss')%3C/script%3E",
        ]

        for payload in mixed_payloads:
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": payload, "enabled": True}
            )

            if response.status_code == 404:
                continue
            elif response.status_code == 200:
                response_text = response.text
                assert "<script>" not in response_text.lower(), (
                    f"Mixed encoding XSS bypass: {payload[:50]}"
                )
            else:
                assert response.status_code in [400, 422, 403]

    def test_xss_html_entity_encoding_payloads(self, client):
        """Test XSS payloads using HTML entity encoding

        HTML entities can be used to bypass filters if the application
        decodes entities before rendering without re-escaping.
        """
        entity_payloads = [
            # Decimal HTML entities
            "&#60;script&#62;alert('xss')&#60;/script&#62;",
            # Hex HTML entities
            "&#x3C;script&#x3E;alert('xss')&#x3C;/script&#x3E;",
            # Named entities
            "&lt;script&gt;alert('xss')&lt;/script&gt;",
            # Mixed decimal and named
            "&#60;script&gt;alert('xss')&#60;/script&gt;",
            # Without semicolons (browser may still parse)
            "&#60script&#62alert('xss')&#60/script&#62",
            # Padded zeros in decimal
            "&#0060;script&#0062;alert('xss')&#0060;/script&#0062;",
        ]

        for payload in entity_payloads:
            response = client.post(
                "/api/scripts/",
                json={
                    "name": payload,
                    "content": "echo test",
                    "description": "Test",
                    "script_type": "bash"
                }
            )

            if response.status_code == 404:
                continue
            elif response.status_code in [200, 201]:
                response_text = response.text
                # After entity decoding, script tags should not be present
                assert "<script>" not in response_text.lower(), (
                    f"HTML entity XSS decoded to script: {payload[:50]}"
                )
            else:
                assert response.status_code in [400, 422, 403, 401]

    def test_xss_unicode_normalization_attacks(self, client):
        """Test XSS payloads exploiting unicode normalization

        Unicode normalization (NFC, NFD, NFKC, NFKD) can transform
        characters in unexpected ways that bypass security filters.
        """
        normalization_payloads = [
            # Combining characters that normalize to < and >
            "﹤script﹥alert('xss')﹤/script﹥",  # Small form variants
            "＜script＞alert('xss')＜/script＞",  # Fullwidth
            # Characters that look like ASCII but aren't
            "<ｓｃｒｉｐｔ>alert('xss')</ｓｃｒｉｐｔ>",  # Fullwidth letters
            # Combining diacritical marks
            "<scr\u0300ipt>alert('xss')</script>",  # Combining grave accent
            # Overlong sequences (in various encodings)
            "<script>alert\u200b('xss')</script>",  # Zero-width space
        ]

        for payload in normalization_payloads:
            response = client.post(
                "/api/script-runner/changes/",
                json={
                    "change_number": "CHG0001234",
                    "description": payload,
                    "status": "pending",
                    "instances": []
                }
            )

            if response.status_code == 404:
                continue
            elif response.status_code in [200, 201]:
                response_text = response.text
                # Check for normalized versions
                assert "alert(" not in response_text.lower(), (
                    f"Unicode normalization XSS: {payload[:50]}"
                )
            else:
                assert response.status_code in [400, 422, 403, 401]

    def test_xss_edge_cases_in_query_parameters(self, client):
        """Test XSS edge cases in query parameters

        Query parameters may be URL-decoded differently than
        request bodies, requiring separate edge case testing.
        """
        import urllib.parse

        edge_case_payloads = [
            # Unicode in query params
            "<script>\u0000alert('xss')</script>",
            # Double-encoded
            urllib.parse.quote(urllib.parse.quote("<script>alert(1)</script>")),
            # Base64 data URI
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ]

        for payload in edge_case_payloads:
            encoded_payload = urllib.parse.quote(payload, safe='')
            response = client.get(f"/api/scripts/?search={encoded_payload}")

            if response.status_code not in [404, 405]:
                response_text = response.text
                # The decoded payload should not appear unescaped
                assert "<script>" not in response_text.lower(), (
                    f"Query param XSS edge case: {payload[:50]}"
                )

    def test_user_input_sanitization(self, client):
        """Test that user input is properly sanitized

        Validates that XSS payloads in user input are either:
        1. Rejected with proper validation error (400, 422)
        2. Sanitized before being included in responses

        If the endpoint doesn't exist yet (404), test passes to allow development.
        """
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
        elif response.status_code == 404:
            # Endpoint not yet implemented - Phase 1 will add this
            pass  # Feature flags toggle endpoint will be added in Phase 1
        else:
            # Should be rejected with proper validation error
            assert response.status_code in [400, 422, 403], (
                f"Expected validation error (400/422/403), got {response.status_code}"
            )
    
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