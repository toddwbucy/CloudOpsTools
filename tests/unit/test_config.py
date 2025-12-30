"""
Unit tests for configuration module

These tests validate the application configuration system that will be
modified during Phase 1 fixes, especially the SECRET_KEY handling.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from backend.core.config import Settings, AWSCredentials, AWSEnvironment

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestSettings:
    """Test application settings configuration"""
    
    def test_default_settings(self):
        """Test default configuration values"""
        settings = Settings()
        
        assert settings.APP_NAME == "PCM-Ops Tools"
        assert settings.VERSION == "2.0.0"
        assert settings.ENVIRONMENT == "development"
        assert settings.DEBUG == True
        assert settings.DEV_MODE == False
        assert settings.HOST == "0.0.0.0"
        assert settings.PORT == 8500
        assert settings.AWS_DEFAULT_REGION == "us-east-1"
        assert settings.SESSION_LIFETIME_MINUTES == 30
        assert settings.MAX_CONCURRENT_EXECUTIONS == 5
        assert settings.EXECUTION_TIMEOUT == 1800
    
    def test_hardcoded_secret_key_default(self):
        """Test that SECRET_KEY has hardcoded default (to be fixed in Phase 1)"""
        settings = Settings()
        
        # This is the current insecure default that Phase 1 will fix
        assert settings.SECRET_KEY == "your-secret-key-here-change-in-production"
    
    def test_database_url_default(self):
        """Test default database URL"""
        # Clear any test database URL override
        with patch.dict(os.environ, {}, clear=False):
            if 'DATABASE_URL' in os.environ:
                del os.environ['DATABASE_URL']
            
            settings = Settings()
            
            assert settings.DATABASE_URL == "sqlite:///./data/pcm_ops_tools.db"
            assert settings.SQLITE_DATABASE_URI == "sqlite:///./data/pcm_ops_tools.db"
    
    def test_cors_origins_default(self):
        """Test default CORS origins"""
        settings = Settings()
        
        expected_origins = ["http://localhost:8500", "http://localhost:3000"]
        assert settings.CORS_ORIGINS == expected_origins
    
    def test_cors_origins_json_parsing(self):
        """Test CORS origins parsing from JSON string"""
        test_origins = '["https://example.com", "https://app.example.com"]'
        
        with patch.dict(os.environ, {'CORS_ORIGINS': test_origins}):
            settings = Settings()
            assert settings.CORS_ORIGINS == ["https://example.com", "https://app.example.com"]
    
    def test_cors_origins_comma_separated_parsing(self):
        """Test CORS origins parsing from comma-separated string"""
        test_origins = "https://example.com,https://app.example.com"
        
        # Test the parsing function directly
        from backend.core.config import Settings
        parsed = Settings.parse_cors_origins(test_origins)
        assert parsed == ["https://example.com", "https://app.example.com"]
    
    def test_cors_origins_invalid_json(self):
        """Test CORS origins handles invalid JSON gracefully"""
        test_origins = 'invalid-json-string'
        
        # Test the parsing function directly
        from backend.core.config import Settings
        parsed = Settings.parse_cors_origins(test_origins)
        assert parsed == ["invalid-json-string"]
    
    def test_directory_creation(self):
        """Test that required directories are created on initialization"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory for this test
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                temp_path = Path(temp_dir)
                upload_path = temp_path / "uploads"
                data_path = Path("./data")  # This will be relative to temp_dir
                
                with patch.dict(os.environ, {'UPLOAD_FOLDER': str(upload_path)}, clear=False):
                    settings = Settings()
                    
                    # Should create upload folder
                    assert upload_path.exists()
                    
                    # Should create data folder
                    assert data_path.exists()
            finally:
                os.chdir(original_cwd)
    
    def test_aws_credentials_none_by_default(self):
        """Test that AWS credentials are None by default"""
        settings = Settings()
        
        # COM credentials
        assert settings.AWS_ACCESS_KEY_ID_COM is None
        assert settings.AWS_SECRET_ACCESS_KEY_COM is None
        assert settings.AWS_SESSION_TOKEN_COM is None
        
        # GOV credentials
        assert settings.AWS_ACCESS_KEY_ID_GOV is None
        assert settings.AWS_SECRET_ACCESS_KEY_GOV is None
        assert settings.AWS_SESSION_TOKEN_GOV is None


class TestAWSCredentialsIntegration:
    """Test AWS credentials integration with Settings"""
    
    def test_get_credentials_com_none(self):
        """Test getting COM credentials when none configured"""
        settings = Settings()
        
        credentials = settings.get_credentials(AWSEnvironment.COM)
        assert credentials is None
    
    def test_get_credentials_gov_none(self):
        """Test getting GOV credentials when none configured"""
        settings = Settings()
        
        credentials = settings.get_credentials(AWSEnvironment.GOV)
        assert credentials is None
    
    def test_get_credentials_com_configured(self):
        """Test getting COM credentials when configured"""
        env_vars = {
            'AWS_ACCESS_KEY_ID_COM': 'ASIAIOSFODNN7EXAMPLE',
            'AWS_SECRET_ACCESS_KEY_COM': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'AWS_SESSION_TOKEN_COM': 'IQoJb3JpZ2luX2VjEJr...',
        }
        
        with patch.dict(os.environ, env_vars):
            settings = Settings()
            credentials = settings.get_credentials(AWSEnvironment.COM)
            
            assert credentials is not None
            assert credentials.access_key == env_vars['AWS_ACCESS_KEY_ID_COM']
            assert credentials.secret_key == env_vars['AWS_SECRET_ACCESS_KEY_COM']
            assert credentials.session_token == env_vars['AWS_SESSION_TOKEN_COM']
            assert credentials.environment == AWSEnvironment.COM
    
    def test_get_credentials_gov_configured(self):
        """Test getting GOV credentials when configured"""
        env_vars = {
            'AWS_ACCESS_KEY_ID_GOV': 'ASIAIOSFODNN7EXAMPLE',
            'AWS_SECRET_ACCESS_KEY_GOV': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'AWS_SESSION_TOKEN_GOV': 'IQoJb3JpZ2luX2VjEJr...',
        }
        
        with patch.dict(os.environ, env_vars):
            settings = Settings()
            credentials = settings.get_credentials(AWSEnvironment.GOV)
            
            assert credentials is not None
            assert credentials.access_key == env_vars['AWS_ACCESS_KEY_ID_GOV']
            assert credentials.secret_key == env_vars['AWS_SECRET_ACCESS_KEY_GOV']
            assert credentials.session_token == env_vars['AWS_SESSION_TOKEN_GOV']
            assert credentials.environment == AWSEnvironment.GOV
    
    def test_get_available_environments_none(self):
        """Test getting available environments when none configured"""
        settings = Settings()
        
        environments = settings.get_available_environments()
        assert environments == []
    
    def test_get_available_environments_com_only(self):
        """Test getting available environments with only COM configured"""
        env_vars = {
            'AWS_ACCESS_KEY_ID_COM': 'test-key',
            'AWS_SECRET_ACCESS_KEY_COM': 'test-secret',
        }
        
        with patch.dict(os.environ, env_vars):
            settings = Settings()
            environments = settings.get_available_environments()
            
            assert environments == [AWSEnvironment.COM]
    
    def test_get_available_environments_both(self):
        """Test getting available environments with both configured"""
        env_vars = {
            'AWS_ACCESS_KEY_ID_COM': 'test-key-com',
            'AWS_SECRET_ACCESS_KEY_COM': 'test-secret-com',
            'AWS_ACCESS_KEY_ID_GOV': 'test-key-gov',
            'AWS_SECRET_ACCESS_KEY_GOV': 'test-secret-gov',
        }
        
        with patch.dict(os.environ, env_vars):
            settings = Settings()
            environments = settings.get_available_environments()
            
            assert len(environments) == 2
            assert AWSEnvironment.COM in environments
            assert AWSEnvironment.GOV in environments


class TestAWSCredentials:
    """Test AWSCredentials model"""
    
    def test_aws_credentials_creation(self):
        """Test creating AWSCredentials instance"""
        credentials = AWSCredentials(
            access_key="ASIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="IQoJb3JpZ2luX2VjEJr...",
            environment=AWSEnvironment.COM,
            expiration=1234567890,
            assumed_role="arn:aws:iam::123456789012:role/test-role",
            access_time=1234567800.0,
        )
        
        assert credentials.access_key == "ASIAIOSFODNN7EXAMPLE"
        assert credentials.secret_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert credentials.session_token == "IQoJb3JpZ2luX2VjEJr..."
        assert credentials.environment == AWSEnvironment.COM
        assert credentials.expiration == 1234567890
        assert credentials.assumed_role == "arn:aws:iam::123456789012:role/test-role"
        assert credentials.access_time == 1234567800.0
    
    def test_aws_credentials_optional_fields(self):
        """Test AWSCredentials with only required fields"""
        credentials = AWSCredentials(
            access_key="ASIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            environment=AWSEnvironment.COM,
        )
        
        assert credentials.session_token is None
        assert credentials.expiration is None
        assert credentials.assumed_role is None
        assert credentials.access_time is None
    
    def test_environment_validation_string_to_enum(self):
        """Test environment validation converts string to enum"""
        credentials = AWSCredentials(
            access_key="test",
            secret_key="test",
            environment="com",  # String instead of enum
        )
        
        assert credentials.environment == AWSEnvironment.COM
        assert isinstance(credentials.environment, AWSEnvironment)
    
    def test_expiration_validation_float_to_int(self):
        """Test expiration validation converts float to int"""
        credentials = AWSCredentials(
            access_key="test",
            secret_key="test", 
            environment=AWSEnvironment.COM,
            expiration=1234567890.5,  # Float
        )
        
        assert credentials.expiration == 1234567890
        assert isinstance(credentials.expiration, int)


class TestAWSEnvironment:
    """Test AWSEnvironment enum"""
    
    def test_aws_environment_values(self):
        """Test AWSEnvironment enum values"""
        assert AWSEnvironment.COM == "com"
        assert AWSEnvironment.GOV == "gov"
    
    def test_aws_environment_creation(self):
        """Test creating AWSEnvironment from string"""
        com_env = AWSEnvironment("com")
        gov_env = AWSEnvironment("gov")
        
        assert com_env == AWSEnvironment.COM
        assert gov_env == AWSEnvironment.GOV
    
    def test_aws_environment_invalid_value(self):
        """Test creating AWSEnvironment with invalid value raises error"""
        with pytest.raises(ValueError):
            AWSEnvironment("invalid")


class TestConfigurationEnvironmentOverrides:
    """Test configuration overrides from environment variables"""
    
    def test_secret_key_environment_override(self):
        """Test SECRET_KEY can be overridden by environment variable"""
        test_secret = "test-secret-key-from-env"
        
        with patch.dict(os.environ, {'SECRET_KEY': test_secret}):
            settings = Settings()
            assert settings.SECRET_KEY == test_secret
    
    def test_database_url_environment_override(self):
        """Test DATABASE_URL can be overridden by environment variable"""
        test_db_url = "sqlite:///./test_database.db"
        
        with patch.dict(os.environ, {'DATABASE_URL': test_db_url}):
            settings = Settings()
            assert settings.DATABASE_URL == test_db_url
    
    def test_debug_mode_environment_override(self):
        """Test DEBUG can be overridden by environment variable"""
        with patch.dict(os.environ, {'DEBUG': 'false'}):
            settings = Settings()
            assert settings.DEBUG == False
        
        with patch.dict(os.environ, {'DEBUG': 'true'}):
            settings = Settings()
            assert settings.DEBUG == True
    
    def test_dev_mode_environment_override(self):
        """Test DEV_MODE can be overridden by environment variable"""
        with patch.dict(os.environ, {'DEV_MODE': 'true'}):
            settings = Settings()
            assert settings.DEV_MODE == True
    
    def test_port_environment_override(self):
        """Test PORT can be overridden by environment variable"""
        with patch.dict(os.environ, {'PORT': '9000'}):
            settings = Settings()
            assert settings.PORT == 9000


class TestSecurityConfiguration:
    """Test security-related configuration"""
    
    def test_secret_key_is_string(self):
        """Test that SECRET_KEY is always a string"""
        settings = Settings()
        assert isinstance(settings.SECRET_KEY, str)
        assert len(settings.SECRET_KEY) > 0
    
    def test_session_lifetime_reasonable(self):
        """Test session lifetime is reasonable"""
        settings = Settings()
        # Should be between 5 minutes and 8 hours
        assert 5 <= settings.SESSION_LIFETIME_MINUTES <= 480
    
    def test_execution_timeout_reasonable(self):
        """Test execution timeout is reasonable"""
        settings = Settings()
        # Should be between 5 minutes and 2 hours
        assert 300 <= settings.EXECUTION_TIMEOUT <= 7200


@pytest.mark.feature_flag
class TestConfigurationForPhase1Changes:
    """Test configuration aspects that will change in Phase 1"""
    
    def test_secret_key_hardcoded_issue(self):
        """Test current hardcoded SECRET_KEY issue (to be fixed)"""
        # Clear any environment SECRET_KEY to test default
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            
            # This is the security issue Phase 1 will fix
            assert settings.SECRET_KEY == "your-secret-key-here-change-in-production"
            
            # This should be considered insecure
            assert "your-secret-key-here" in settings.SECRET_KEY.lower()
    
    def test_environment_variable_secret_key_works(self):
        """Test that environment variable SECRET_KEY override works (Phase 1 fix)"""
        secure_secret = "properly-generated-secret-key-123456"
        
        with patch.dict(os.environ, {'SECRET_KEY': secure_secret}):
            settings = Settings()
            assert settings.SECRET_KEY == secure_secret
            assert settings.SECRET_KEY != "your-secret-key-here-change-in-production"
    
    def test_cors_configuration_security(self):
        """Test CORS configuration for security"""
        settings = Settings()
        
        # Default should only allow localhost for development
        for origin in settings.CORS_ORIGINS:
            assert origin.startswith("http://localhost")
    
    def test_session_cookie_security_ready(self):
        """Test that configuration is ready for secure session cookies"""
        settings = Settings()
        
        # These settings should be compatible with secure cookies
        assert isinstance(settings.SECRET_KEY, str)
        assert len(settings.SECRET_KEY) >= 32  # Minimum for secure sessions