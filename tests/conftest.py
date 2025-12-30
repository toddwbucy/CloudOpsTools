"""
Global test configuration and fixtures for PCM-Ops Tools

This module provides shared test fixtures and configuration that can be used
across all test modules. It includes database setup, client fixtures, and
common test utilities.
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator
from unittest.mock import Mock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Import application components
from backend.core.config import settings
from backend.core.feature_flags import FeatureFlagsConfig, FeatureFlagManager
from backend.db.base import Base
from backend.db.session import get_db
from backend.main import app


# ============================================================================
# Test Environment Setup
# ============================================================================

@pytest.fixture(scope="session")
def test_settings():
    """Override settings for testing"""
    original_values = {}
    
    # Store original values
    test_overrides = {
        "ENVIRONMENT": "test",
        "DEBUG": True,
        "DATABASE_URL": "sqlite:///./test_database.db",
        "SECRET_KEY": "test-secret-key-for-testing-only",
        "DEV_MODE": True,
    }
    
    for key, value in test_overrides.items():
        original_values[key] = getattr(settings, key)
        setattr(settings, key, value)
    
    yield settings
    
    # Restore original values
    for key, value in original_values.items():
        setattr(settings, key, value)


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def test_db():
    """Create a test database for each test function"""
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    test_db_url = f"sqlite:///{db_path}"
    
    # Create engine and tables
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    
    # Create session
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    yield TestingSessionLocal()
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture(scope="function")
def db_session(test_db):
    """Provide database session for tests"""
    session = test_db
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def override_get_db(db_session):
    """Override database dependency for testing"""
    def _override():
        try:
            yield db_session
        finally:
            pass  # Session cleanup handled by fixture
    return _override


# ============================================================================
# Application Client Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def client(test_settings, db_session):
    """Create FastAPI test client"""
    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db(db_session)
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Clean up dependency override
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
async def async_client(test_settings, db_session):
    """Create async test client for async endpoints"""
    app.dependency_overrides[get_db] = override_get_db(db_session)
    
    async with AsyncClient(app=app, base_url="http://test") as async_test_client:
        yield async_test_client
    
    app.dependency_overrides.clear()


# ============================================================================
# Feature Flag Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def feature_flags():
    """Create test feature flag manager"""
    test_config = FeatureFlagsConfig(
        DEBUG_MODE_ENABLED=True,
        STAGING_MODE_ENABLED=False,
        ROLLBACK_MODE_ENABLED=False,
        # All Phase 1 flags disabled by default for safety
        NEW_SECRET_KEY_HANDLING="disabled",
        XSS_PROTECTION_ENABLED="disabled",
        CSRF_TOKENS_ENABLED="disabled",
        SECURE_CREDENTIAL_STORAGE="disabled",
        STRUCTURED_LOGGING="disabled",
    )
    
    return FeatureFlagManager()


@pytest.fixture(scope="function")
def enabled_feature_flag(feature_flags):
    """Feature flag manager with specific flag enabled for testing"""
    def _enable_flag(flag_name: str):
        feature_flags.enable_flag(flag_name)
        return feature_flags
    return _enable_flag


# ============================================================================
# Mock Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def mock_aws_credentials():
    """Mock AWS credentials for testing"""
    return {
        "access_key": "ASIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 
        "session_token": "IQoJb3JpZ2luX2VjEJr...very-long-token...",
        "environment": "com",
        "expiration": 1234567890,
    }


@pytest.fixture(scope="function")
def mock_boto3_client():
    """Mock boto3 client for AWS operations"""
    mock_client = Mock()
    
    # Mock common AWS responses
    mock_client.get_caller_identity.return_value = {
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        "Account": "123456789012", 
        "Arn": "arn:aws:iam::123456789012:user/testuser"
    }
    
    mock_client.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1234567890abcdef0",
                        "State": {"Name": "running"},
                        "InstanceType": "t3.micro",
                        "Platform": "linux"
                    }
                ]
            }
        ]
    }
    
    return mock_client


# ============================================================================
# Data Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def sample_script_data():
    """Sample script data for testing"""
    return {
        "name": "Test Script",
        "content": "#!/bin/bash\necho 'Hello World'",
        "description": "A test script for validation",
        "platform": "linux",
        "script_type": "bash",
    }


@pytest.fixture(scope="function")
def sample_execution_data():
    """Sample execution data for testing"""
    return {
        "script_id": 1,
        "instance_ids": ["i-1234567890abcdef0"],
        "accounts": ["123456789012"],
        "regions": ["us-east-1"],
        "execution_type": "single",
    }


# ============================================================================
# Cleanup and Utilities
# ============================================================================

@pytest.fixture(scope="function", autouse=True)
def cleanup_test_files():
    """Automatically clean up test files after each test"""
    yield
    
    # Clean up any test database files
    test_files = Path('.').glob('test_*.db')
    for test_file in test_files:
        try:
            test_file.unlink()
        except FileNotFoundError:
            pass


@pytest.fixture(scope="function")
def temp_directory():
    """Provide temporary directory for test file operations"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


# ============================================================================
# Security Testing Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def security_test_payloads():
    """Common security test payloads"""
    return {
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
        ],
        "sql_injection_payloads": [
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT null,null,null --",
        ],
        "csrf_tokens": [
            "",  # Empty token
            "invalid-token",
            "expired-token-12345",
        ],
        "malicious_filenames": [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\hosts",
            "file.php%00.jpg",
        ]
    }


# ============================================================================
# Performance Testing Fixtures  
# ============================================================================

@pytest.fixture(scope="function")
def performance_thresholds():
    """Performance thresholds for testing"""
    return {
        "health_check_max_time": 1.0,  # seconds
        "api_response_max_time": 2.0,  # seconds
        "web_page_max_time": 3.0,  # seconds
        "database_query_max_time": 0.5,  # seconds
    }


# ============================================================================
# Test Markers and Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers and settings"""
    # Register custom markers
    config.addinivalue_line(
        "markers", "critical: mark test as critical path functionality"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-related"
    )
    config.addinivalue_line(
        "markers", "feature_flag: mark test as requiring feature flags"
    )
    config.addinivalue_line(
        "markers", "rollback: mark test as rollback functionality"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on file location"""
    for item in items:
        # Add markers based on file path
        if "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        if "critical" in str(item.fspath):
            item.add_marker(pytest.mark.critical)
        if "feature_flag" in str(item.fspath):
            item.add_marker(pytest.mark.feature_flag)


# ============================================================================
# Test Data Factories (using factory_boy will be added separately)
# ============================================================================

class TestDataFactory:
    """Factory for creating test data objects"""
    
    @staticmethod
    def create_user_data(**kwargs):
        """Create test user data"""
        defaults = {
            "username": "testuser",
            "email": "test@example.com",
            "is_active": True,
        }
        defaults.update(kwargs)
        return defaults
    
    @staticmethod
    def create_aws_account_data(**kwargs):
        """Create test AWS account data"""
        defaults = {
            "account_id": "123456789012",
            "account_name": "test-account",
            "environment": "com",
            "regions": ["us-east-1"],
        }
        defaults.update(kwargs)
        return defaults