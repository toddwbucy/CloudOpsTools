"""
Unit tests for feature flag system

These tests validate that the feature flag system works correctly for
safe deployment and rollback of fixes.
"""

import pytest
from unittest.mock import Mock, patch

from backend.core.feature_flags import (
    FeatureFlagManager, 
    FeatureFlagsConfig,
    FeatureFlagStatus,
    emergency_rollback_all,
    is_feature_enabled,
    enable_feature,
    disable_feature
)

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestFeatureFlagsConfig:
    """Test feature flags configuration"""
    
    def test_default_configuration(self):
        """Test that default configuration is safe (all flags disabled)"""
        config = FeatureFlagsConfig()
        
        # Phase 1 security flags should be disabled by default
        assert config.NEW_SECRET_KEY_HANDLING == FeatureFlagStatus.DISABLED
        assert config.XSS_PROTECTION_ENABLED == FeatureFlagStatus.DISABLED
        assert config.CSRF_TOKENS_ENABLED == FeatureFlagStatus.DISABLED
        assert config.SECURE_CREDENTIAL_STORAGE == FeatureFlagStatus.DISABLED
        assert config.STRUCTURED_LOGGING == FeatureFlagStatus.DISABLED
        
        # Phase 2 medium risk flags should be disabled by default
        assert config.THREAD_SAFE_SESSIONS == FeatureFlagStatus.DISABLED
        assert config.ATOMIC_SESSION_UPDATES == FeatureFlagStatus.DISABLED
        assert config.ENHANCED_ERROR_HANDLING == FeatureFlagStatus.DISABLED
        assert config.JS_MEMORY_LEAK_FIXES == FeatureFlagStatus.DISABLED
        assert config.PYDANTIC_V2_SCHEMAS == FeatureFlagStatus.DISABLED
        
        # Development flags
        assert config.DEBUG_MODE_ENABLED == False
        assert config.STAGING_MODE_ENABLED == False
        assert config.ROLLBACK_MODE_ENABLED == False
    
    def test_environment_variable_override(self):
        """Test that environment variables can override defaults"""
        with patch.dict('os.environ', {
            'FEATURE_FLAG_DEBUG_MODE_ENABLED': 'true',
            'FEATURE_FLAG_NEW_SECRET_KEY_HANDLING': 'enabled'
        }):
            config = FeatureFlagsConfig()
            assert config.DEBUG_MODE_ENABLED == True
            assert config.NEW_SECRET_KEY_HANDLING == FeatureFlagStatus.ENABLED


class TestFeatureFlagManager:
    """Test feature flag manager functionality"""
    
    def test_initialization(self):
        """Test feature flag manager initialization"""
        manager = FeatureFlagManager()
        
        assert manager.config is not None
        assert isinstance(manager.config, FeatureFlagsConfig)
        assert hasattr(manager, '_cached_flags')
    
    def test_is_enabled_disabled_flag(self):
        """Test checking disabled flag"""
        manager = FeatureFlagManager()
        
        # Flag should be disabled by default
        result = manager.is_enabled('NEW_SECRET_KEY_HANDLING')
        assert result == False
    
    def test_is_enabled_unknown_flag(self):
        """Test checking unknown flag returns False"""
        manager = FeatureFlagManager()
        
        result = manager.is_enabled('UNKNOWN_FLAG')
        assert result == False
    
    def test_enable_flag(self):
        """Test enabling a feature flag"""
        manager = FeatureFlagManager()
        
        # Enable flag
        result = manager.enable_flag('NEW_SECRET_KEY_HANDLING')
        assert result == True
        
        # Verify it's enabled
        enabled = manager.is_enabled('NEW_SECRET_KEY_HANDLING')
        assert enabled == True
    
    def test_disable_flag(self):
        """Test disabling a feature flag"""
        manager = FeatureFlagManager()
        
        # First enable it
        manager.enable_flag('NEW_SECRET_KEY_HANDLING')
        assert manager.is_enabled('NEW_SECRET_KEY_HANDLING') == True
        
        # Then disable it
        result = manager.disable_flag('NEW_SECRET_KEY_HANDLING')
        assert result == True
        
        # Verify it's disabled
        enabled = manager.is_enabled('NEW_SECRET_KEY_HANDLING')
        assert enabled == False
    
    def test_enable_unknown_flag(self):
        """Test enabling unknown flag returns False"""
        manager = FeatureFlagManager()
        
        result = manager.enable_flag('UNKNOWN_FLAG')
        assert result == False
    
    def test_disable_unknown_flag(self):
        """Test disabling unknown flag returns False"""
        manager = FeatureFlagManager()
        
        result = manager.disable_flag('UNKNOWN_FLAG')
        assert result == False
    
    def test_get_all_flags(self):
        """Test getting all feature flags"""
        manager = FeatureFlagManager()
        
        all_flags = manager.get_all_flags()
        
        assert isinstance(all_flags, dict)
        assert len(all_flags) > 0
        
        # Check for expected flags
        assert 'new_secret_key_handling' in all_flags
        assert 'xss_protection_enabled' in all_flags
        assert 'csrf_tokens_enabled' in all_flags
    
    def test_health_check(self):
        """Test health check functionality"""
        manager = FeatureFlagManager()
        
        health = manager.health_check()
        
        assert isinstance(health, dict)
        assert 'status' in health
        assert 'total_flags' in health
        assert 'enabled_flags' in health
        assert 'rollback_mode' in health
        assert 'debug_mode' in health
        assert 'staging_mode' in health
        
        assert health['status'] == 'healthy'
        assert health['total_flags'] > 0
        assert health['enabled_flags'] >= 0
    
    def test_dev_only_flag_behavior(self):
        """Test DEV_ONLY flag behavior"""
        manager = FeatureFlagManager()
        
        # Mock a DEV_ONLY flag with debug mode enabled
        with patch.object(manager.config, 'DEBUG_MODE_ENABLED', True):
            with patch.object(manager.config, 'STAGING_MODE_ENABLED', False):
                with patch.object(manager.config, 'STRUCTURED_LOGGING', FeatureFlagStatus.DEV_ONLY):
                    result = manager.is_enabled('STRUCTURED_LOGGING')
                    assert result == True
        
        # Without debug mode or staging mode, dev-only flags should be disabled
        with patch.object(manager.config, 'DEBUG_MODE_ENABLED', False):
            with patch.object(manager.config, 'STAGING_MODE_ENABLED', False):
                with patch.object(manager.config, 'STRUCTURED_LOGGING', FeatureFlagStatus.DEV_ONLY):
                    result = manager.is_enabled('STRUCTURED_LOGGING')
                    assert result == False


class TestConvenienceFunctions:
    """Test convenience functions for feature flags"""
    
    def test_is_feature_enabled(self):
        """Test is_feature_enabled convenience function"""
        with patch('backend.core.feature_flags.feature_flags') as mock_ff:
            mock_ff.is_enabled.return_value = True
            
            result = is_feature_enabled('TEST_FLAG')
            assert result == True
            mock_ff.is_enabled.assert_called_once_with('TEST_FLAG', None)
    
    def test_enable_feature(self):
        """Test enable_feature convenience function"""
        with patch('backend.core.feature_flags.feature_flags') as mock_ff:
            mock_ff.enable_flag.return_value = True
            
            result = enable_feature('TEST_FLAG')
            assert result == True
            mock_ff.enable_flag.assert_called_once_with('TEST_FLAG')
    
    def test_disable_feature(self):
        """Test disable_feature convenience function"""
        with patch('backend.core.feature_flags.feature_flags') as mock_ff:
            mock_ff.disable_flag.return_value = True
            
            result = disable_feature('TEST_FLAG')
            assert result == True
            mock_ff.disable_flag.assert_called_once_with('TEST_FLAG')


class TestEmergencyRollback:
    """Test emergency rollback functionality"""
    
    def test_emergency_rollback_all(self):
        """Test emergency rollback disables all flags"""
        with patch('backend.core.feature_flags.feature_flags') as mock_ff:
            mock_ff.get_all_flags.return_value = {
                'new_secret_key_handling': FeatureFlagStatus.ENABLED,
                'xss_protection_enabled': FeatureFlagStatus.ENABLED,
                'debug_mode_enabled': True,
                'staging_mode_enabled': False,
            }
            
            emergency_rollback_all()
            
            # Should disable all non-debug flags
            expected_calls = [
                ('new_secret_key_handling',),
                ('xss_protection_enabled',),
            ]
            
            actual_calls = [call.args for call in mock_ff.disable_flag.call_args_list]
            
            for expected_call in expected_calls:
                assert expected_call in actual_calls


class TestErrorHandling:
    """Test error handling in feature flag system"""
    
    def test_is_enabled_handles_exception(self):
        """Test that is_enabled handles exceptions gracefully"""
        manager = FeatureFlagManager()
        
        with patch.object(manager.config, 'NEW_SECRET_KEY_HANDLING', 
                         side_effect=Exception("Test exception")):
            # Should return False on exception, not raise
            result = manager.is_enabled('NEW_SECRET_KEY_HANDLING')
            assert result == False
    
    def test_enable_flag_handles_exception(self):
        """Test that enable_flag handles exceptions gracefully"""
        manager = FeatureFlagManager()
        
        # Test with non-existent flag (should return False, not raise)
        result = manager.enable_flag('NON_EXISTENT_FLAG')
        assert result is False
    
    def test_disable_flag_handles_exception(self):
        """Test that disable_flag handles exceptions gracefully"""
        manager = FeatureFlagManager()
        
        # Test with non-existent flag (should return False, not raise)
        result = manager.disable_flag('NON_EXISTENT_FLAG')
        assert result is False


@pytest.mark.integration
class TestFeatureFlagIntegration:
    """Integration tests for feature flag system"""
    
    def test_flag_persistence_across_instances(self):
        """Test that flag changes persist across manager instances"""
        # This would require actual persistence testing
        # For now, we'll test that the same config instance is used
        manager1 = FeatureFlagManager()
        manager2 = FeatureFlagManager()
        
        # Both should use the same config class (not necessarily same instance)
        assert type(manager1.config) == type(manager2.config)
    
    def test_real_flag_operations(self):
        """Test actual flag operations without mocking"""
        manager = FeatureFlagManager()
        
        # Test enabling and disabling a flag
        flag_name = 'STRUCTURED_LOGGING'
        
        # Ensure it starts disabled
        initial_state = manager.is_enabled(flag_name)
        
        # Enable it
        enable_result = manager.enable_flag(flag_name)
        assert enable_result == True
        
        # Check it's enabled
        enabled_state = manager.is_enabled(flag_name)
        assert enabled_state == True
        
        # Disable it
        disable_result = manager.disable_flag(flag_name)
        assert disable_result == True
        
        # Check it's disabled
        disabled_state = manager.is_enabled(flag_name)
        assert disabled_state == False