"""
Tests for rate limiting functionality.

These tests verify that rate limiting is properly configured and that
HTTP 429 responses include the Retry-After header as required by RFC 6585.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture(autouse=True)
def reset_limiter():
    """Reset rate limiter state before each test to ensure test isolation.

    This fixture runs automatically before each test to clear the limiter's
    in-memory storage, preventing tests from affecting each other due to
    accumulated rate limit counters.
    """
    # Clear the limiter's storage before each test
    if hasattr(app.state, "limiter") and app.state.limiter:
        # SlowAPI's in-memory storage can be cleared via the storage backend
        if hasattr(app.state.limiter, "_storage"):
            app.state.limiter._storage.storage.clear()
    yield
    # Cleanup after test (optional, but good practice)
    if hasattr(app.state, "limiter") and app.state.limiter:
        if hasattr(app.state.limiter, "_storage"):
            app.state.limiter._storage.storage.clear()


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    return TestClient(app)


class TestRateLimitingRetryAfterHeader:
    """Test that rate limiting returns proper Retry-After headers."""

    def test_auth_endpoint_returns_429_with_retry_after_header(self, client):
        """
        Test that exceeding auth endpoint rate limit returns HTTP 429
        with a Retry-After header.

        The Retry-After header is required by RFC 6585 for 429 responses
        and tells the client how long to wait before retrying.
        """
        # Valid credentials for testing (meets minimum length requirements)
        test_credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "environment": "com"
        }

        # Make requests up to and beyond the rate limit (10/minute for auth)
        # We need to exceed the limit to trigger 429
        responses = []
        for i in range(12):
            response = client.post(
                "/api/auth/aws-credentials",
                json=test_credentials
            )
            responses.append(response)

            # Once we get a 429, verify the Retry-After header
            if response.status_code == 429:
                assert "retry-after" in response.headers, (
                    "HTTP 429 response must include Retry-After header"
                )

                # Verify Retry-After contains a valid integer (seconds to wait)
                retry_after = response.headers["retry-after"]
                assert retry_after.isdigit(), (
                    f"Retry-After header must be a number of seconds, got: {retry_after}"
                )

                # Verify the value is reasonable (should be <= 60 seconds for per-minute limits)
                retry_seconds = int(retry_after)
                assert 0 < retry_seconds <= 60, (
                    f"Retry-After should be between 1-60 seconds, got: {retry_seconds}"
                )

                # Test passed - we got 429 with valid Retry-After
                return

        # If we made all requests without hitting 429, that's a problem
        status_codes = [r.status_code for r in responses]
        pytest.fail(
            f"Expected HTTP 429 after exceeding rate limit, but got: {status_codes}"
        )

    def test_execution_endpoint_returns_429_with_retry_after_header(self, client):
        """
        Test that exceeding execution endpoint rate limit returns HTTP 429
        with a Retry-After header.

        Execution endpoints have a 5/minute limit.
        """
        # Make requests up to and beyond the rate limit (5/minute for execution)
        responses = []
        for i in range(7):
            response = client.post("/api/tools/test-tool/execute")
            responses.append(response)

            # Once we get a 429, verify the Retry-After header
            if response.status_code == 429:
                assert "retry-after" in response.headers, (
                    "HTTP 429 response must include Retry-After header"
                )

                retry_after = response.headers["retry-after"]
                assert retry_after.isdigit(), (
                    f"Retry-After header must be a number of seconds, got: {retry_after}"
                )

                retry_seconds = int(retry_after)
                assert 0 < retry_seconds <= 60, (
                    f"Retry-After should be between 1-60 seconds, got: {retry_seconds}"
                )

                return

        status_codes = [r.status_code for r in responses]
        pytest.fail(
            f"Expected HTTP 429 after exceeding rate limit, but got: {status_codes}"
        )

    def test_read_endpoint_returns_429_with_retry_after_header(self, client):
        """
        Test that exceeding read endpoint rate limit returns HTTP 429
        with a Retry-After header.

        Read endpoints have a 100/minute limit - we'll use a smaller test limit.
        """
        # For read endpoints, the limit is 100/minute
        # We'll make 102 requests to ensure we exceed the limit
        responses = []
        for i in range(102):
            response = client.get("/api/tools/")
            responses.append(response)

            # Once we get a 429, verify the Retry-After header
            if response.status_code == 429:
                assert "retry-after" in response.headers, (
                    "HTTP 429 response must include Retry-After header"
                )

                retry_after = response.headers["retry-after"]
                assert retry_after.isdigit(), (
                    f"Retry-After header must be a number of seconds, got: {retry_after}"
                )

                retry_seconds = int(retry_after)
                assert 0 < retry_seconds <= 60, (
                    f"Retry-After should be between 1-60 seconds, got: {retry_seconds}"
                )

                return

        status_codes = [r.status_code for r in responses]
        pytest.fail(
            f"Expected HTTP 429 after exceeding rate limit, but got: {status_codes}"
        )

    def test_429_response_body_contains_error_message(self, client):
        """
        Test that 429 responses include a meaningful error message.
        """
        test_credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "environment": "com"
        }

        # Exceed the rate limit
        for i in range(12):
            response = client.post(
                "/api/auth/aws-credentials",
                json=test_credentials
            )

            if response.status_code == 429:
                # Verify response body contains error information
                response_data = response.json()
                assert "error" in response_data or "detail" in response_data, (
                    "429 response should contain error message"
                )
                return

        pytest.fail("Expected to hit rate limit but did not receive 429")


class TestRateLimitingConfiguration:
    """Test that rate limiting is properly configured."""

    def test_health_endpoint_shows_rate_limiting_enabled(self, client):
        """Test that /api/health reports rate limiting as enabled."""
        response = client.get("/api/health")
        assert response.status_code == 200

        data = response.json()
        assert "services" in data
        assert "rate_limiting" in data["services"]

        rate_limiting = data["services"]["rate_limiting"]
        assert rate_limiting["status"] in ("enabled", "degraded")
        assert "configuration" in rate_limiting
        assert "auth_endpoints" in rate_limiting["configuration"]
        assert "execution_endpoints" in rate_limiting["configuration"]
        assert "read_endpoints" in rate_limiting["configuration"]

    def test_limiter_attached_to_app_state(self):
        """Test that the limiter is properly attached to app.state."""
        assert hasattr(app.state, "limiter"), "Limiter must be attached to app.state"
        assert app.state.limiter is not None, "Limiter must not be None"
