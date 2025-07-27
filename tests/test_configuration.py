"""
Tests for aiows configuration system
"""

import os
import pytest
import tempfile
import time
from pathlib import Path
from unittest import mock

from aiows.config import (
    BaseConfig, ConfigValue, ConfigValidationError, ConfigMeta,
    positive_int, positive_number, valid_port, valid_host, 
    non_empty_string, valid_log_level, min_length, in_range, in_choices
)
from aiows.settings import (
    ServerConfig, RateLimitConfig, ConnectionLimiterConfig, 
    AuthConfig, LoggingConfig, SecurityConfig, AiowsSettings, create_settings
)


class TestConfigValue:
    """Test ConfigValue descriptor"""
    
    def test_basic_functionality(self):
        class TestConfig(BaseConfig):
            test_value = ConfigValue(default="default_value", description="Test value")
        
        config = TestConfig()
        assert config.test_value == "default_value"
    
    def test_environment_variable_override(self):
        with mock.patch.dict(os.environ, {'AIOWS_TEST_VALUE': 'env_value'}):
            class TestConfig(BaseConfig):
                test_value = ConfigValue(default="default_value")
            
            config = TestConfig()
            assert config.test_value == "env_value"
    
    def test_type_casting(self):
        with mock.patch.dict(os.environ, {
            'AIOWS_INT_VALUE': '42',
            'AIOWS_FLOAT_VALUE': '3.14',
            'AIOWS_BOOL_VALUE': 'true',
            'AIOWS_LIST_VALUE': 'item1,item2,item3'
        }):
            class TestConfig(BaseConfig):
                int_value = ConfigValue(default=0, type_cast=int)
                float_value = ConfigValue(default=0.0, type_cast=float)
                bool_value = ConfigValue(default=False, type_cast=bool)
                list_value = ConfigValue(default=[], type_cast=list)
            
            config = TestConfig()
            assert config.int_value == 42
            assert config.float_value == 3.14
            assert config.bool_value is True
            assert config.list_value == ['item1', 'item2', 'item3']
    
    def test_boolean_parsing(self):
        test_cases = [
            ('true', True), ('TRUE', True), ('1', True), ('yes', True), ('on', True),
            ('false', False), ('FALSE', False), ('0', False), ('no', False), ('off', False)
        ]
        
        for env_value, expected in test_cases:
            with mock.patch.dict(os.environ, {'AIOWS_BOOL_TEST': env_value}):
                class TestConfig(BaseConfig):
                    bool_test = ConfigValue(default=False, type_cast=bool)
                
                config = TestConfig()
                assert config.bool_test is expected, f"Failed for {env_value}"
    
    def test_validation(self):
        class TestConfig(BaseConfig):
            positive_value = ConfigValue(default=1, validator=positive_int, type_cast=int)
        
        config = TestConfig()
        assert config.positive_value == 1
        
        with pytest.raises(ConfigValidationError):
            config.positive_value = -1
    
    def test_required_values(self):
        class TestConfig(BaseConfig):
            required_value = ConfigValue(required=True, type_cast=str)
        
        with pytest.raises(ConfigValidationError, match="Required configuration"):
            TestConfig()
        
        with mock.patch.dict(os.environ, {'AIOWS_REQUIRED_VALUE': 'test'}):
            config = TestConfig()
            assert config.required_value == 'test'
    
    def test_sensitive_values(self):
        class TestConfig(BaseConfig):
            secret = ConfigValue(default="secret_value", sensitive=True)
        
        config = TestConfig()
        info = config.get_config_info()
        assert info['values']['secret']['value'] == '***HIDDEN***'
        
        config_dict = config.to_dict(include_sensitive=True)
        assert config_dict['secret'] == 'secret_value'
    
    def test_cache_behavior(self):
        class TestConfig(BaseConfig):
            cached_value = ConfigValue(default="initial")
        
        config = TestConfig()
        assert config.cached_value == "initial"
        
        config.cached_value = "changed"
        assert config.cached_value == "changed"
        
        config._config_values['cached_value'].clear_cache(config)
        assert config.cached_value == "initial"


class TestValidators:
    """Test configuration validators"""
    
    def test_positive_int(self):
        assert positive_int(1) is True
        assert positive_int(100) is True
        assert positive_int(0) is False
        assert positive_int(-1) is False
        assert positive_int(3.14) is False
        assert positive_int("string") is False
    
    def test_positive_number(self):
        assert positive_number(1) is True
        assert positive_number(1.5) is True
        assert positive_number(0) is False
        assert positive_number(-1) is False
        assert positive_number("string") is False
    
    def test_valid_port(self):
        assert valid_port(80) is True
        assert valid_port(8080) is True
        assert valid_port(65535) is True
        assert valid_port(0) is False
        assert valid_port(65536) is False
        assert valid_port(-1) is False
        assert valid_port("string") is False
    
    def test_valid_host(self):
        assert valid_host("localhost") is True
        assert valid_host("0.0.0.0") is True
        assert valid_host("example.com") is True
        assert valid_host("") is False
        assert valid_host("   ") is False
        assert valid_host(123) is False
    
    def test_non_empty_string(self):
        assert non_empty_string("test") is True
        assert non_empty_string("") is False
        assert non_empty_string("   ") is False
        assert non_empty_string(123) is False
    
    def test_valid_log_level(self):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        for level in valid_levels:
            assert valid_log_level(level) is True
            assert valid_log_level(level.lower()) is True
        
        assert valid_log_level("INVALID") is False
        assert valid_log_level(123) is False
    
    def test_min_length(self):
        validator = min_length(5)
        assert validator("12345") is True
        assert validator("123456") is True
        assert validator("1234") is False
        assert validator(123) is False
    
    def test_in_range(self):
        validator = in_range(1, 10)
        assert validator(1) is True
        assert validator(5) is True
        assert validator(10) is True
        assert validator(0) is False
        assert validator(11) is False
        assert validator("string") is False
    
    def test_in_choices(self):
        validator = in_choices(['a', 'b', 'c'])
        assert validator('a') is True
        assert validator('b') is True
        assert validator('d') is False
        assert validator(1) is False


class TestBaseConfig:
    """Test BaseConfig functionality"""
    
    def test_config_info(self):
        class TestConfig(BaseConfig):
            test_value = ConfigValue(default="test", description="Test description")
        
        config = TestConfig()
        info = config.get_config_info()
        
        assert 'load_timestamp' in info
        assert 'validation_errors' in info
        assert 'values' in info
        assert 'test_value' in info['values']
        assert info['values']['test_value']['description'] == "Test description"
    
    def test_to_dict(self):
        class TestConfig(BaseConfig):
            public_value = ConfigValue(default="public")
            secret_value = ConfigValue(default="secret", sensitive=True)
        
        config = TestConfig()
        
        config_dict = config.to_dict()
        assert config_dict['public_value'] == 'public'
        assert config_dict['secret_value'] == '***HIDDEN***'
        
        config_dict = config.to_dict(include_sensitive=True)
        assert config_dict['public_value'] == 'public'
        assert config_dict['secret_value'] == 'secret'
    
    def test_update_from_dict(self):
        class TestConfig(BaseConfig):
            value1 = ConfigValue(default="default1")
            value2 = ConfigValue(default="default2")
        
        config = TestConfig()
        config.update_from_dict({
            'value1': 'updated1',
            'value2': 'updated2',
            'unknown_key': 'ignored'
        })
        
        assert config.value1 == 'updated1'
        assert config.value2 == 'updated2'
    
    def test_reload(self):
        class TestConfig(BaseConfig):
            test_value = ConfigValue(default="default")
        
        config = TestConfig()
        assert config.test_value == "default"
        
        with mock.patch.dict(os.environ, {'AIOWS_TEST_VALUE': 'reloaded'}):
            config.reload()
            assert config.test_value == "reloaded"
    
    def test_export_env_template(self):
        class TestConfig(BaseConfig):
            public_value = ConfigValue(default="public", description="Public setting")
            secret_value = ConfigValue(default="secret", sensitive=True, description="Secret setting")
        
        config = TestConfig()
        template = config.export_env_template()
        
        assert "Public setting" in template
        assert "Secret setting" in template
        assert "AIOWS_PUBLIC_VALUE=public" in template
        assert "AIOWS_SECRET_VALUE=***CHANGE_ME***" in template
    
    def test_validation_on_init(self):
        class TestConfig(BaseConfig):
            invalid_value = ConfigValue(default=-1, validator=positive_int, type_cast=int)
        
        with pytest.raises(ConfigValidationError):
            TestConfig()


class TestServerConfig:
    """Test ServerConfig class"""
    
    def test_default_values(self):
        config = ServerConfig()
        assert config.host == "localhost"
        assert config.port == 8000
        assert config.is_production is False
        assert config.shutdown_timeout == 30.0
        assert config.cleanup_interval == 30.0
    
    def test_environment_override(self):
        with mock.patch.dict(os.environ, {
            'AIOWS_HOST': '0.0.0.0',
            'AIOWS_PORT': '9000',
            'AIOWS_IS_PRODUCTION': 'true'
        }):
            config = ServerConfig()
            assert config.host == "0.0.0.0"
            assert config.port == 9000
            assert config.is_production is True
    
    def test_validation(self):
        config = ServerConfig()
        
        with pytest.raises(ConfigValidationError):
            config.port = 0
        
        with pytest.raises(ConfigValidationError):
            config.shutdown_timeout = -1


class TestAiowsSettings:
    """Test AiowsSettings main configuration class"""
    
    def test_default_profile(self):
        settings = AiowsSettings()
        assert settings.profile == "development"
        assert settings.server.is_production is False
        assert settings.logging.log_level == "DEBUG"
    
    def test_production_profile(self):
        settings = AiowsSettings(profile="production")
        assert settings.profile == "production"
        assert settings.server.is_production is True
        assert settings.server.host == "0.0.0.0"
        assert settings.logging.log_level == "WARNING"
        assert settings.logging.use_json_format is True
        assert settings.rate_limit.max_messages_per_minute == 30
    
    def test_testing_profile(self):
        settings = AiowsSettings(profile="testing")
        assert settings.profile == "testing"
        assert settings.server.port == 8001
        assert settings.logging.log_level == "ERROR"
        assert settings.rate_limit.max_messages_per_minute == 1000
        assert settings.connection_limiter.max_connections_per_ip == 100
    
    def test_unknown_profile(self):
        with pytest.raises(ConfigValidationError, match="Unknown profile"):
            AiowsSettings(profile="unknown")
    
    def test_reload_functionality(self):
        settings = AiowsSettings()
        original_host = settings.server.host
        
        with mock.patch.dict(os.environ, {'AIOWS_HOST': 'changed.host'}):
            settings.reload()
            assert settings.server.host == 'changed.host'
    
    def test_config_info(self):
        settings = AiowsSettings()
        info = settings.get_config_info()
        
        assert 'profile' in info
        assert 'configs' in info
        assert 'server' in info['configs']
        assert 'rate_limit' in info['configs']
        assert 'auth' in info['configs']
    
    def test_to_dict(self):
        settings = AiowsSettings()
        settings_dict = settings.to_dict()
        
        assert 'profile' in settings_dict
        assert 'server' in settings_dict
        assert 'rate_limit' in settings_dict
    
    def test_env_template_export(self):
        settings = AiowsSettings()
        template = settings.export_env_template()
        
        assert "aiows Framework Configuration" in template
        assert "AIOWS_HOST" in template
        assert "AIOWS_PORT" in template
        assert "SERVER CONFIGURATION" in template


class TestCreateSettings:
    """Test create_settings convenience function"""
    
    def test_default_profile_from_env(self):
        with mock.patch.dict(os.environ, {'AIOWS_PROFILE': 'production'}):
            settings = create_settings()
            assert settings.profile == "production"
    
    def test_explicit_profile_override(self):
        with mock.patch.dict(os.environ, {'AIOWS_PROFILE': 'production'}):
            settings = create_settings(profile="testing")
            assert settings.profile == "testing"
    
    def test_default_fallback(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            if 'AIOWS_PROFILE' in os.environ:
                del os.environ['AIOWS_PROFILE']
            settings = create_settings()
            assert settings.profile == "development"


class TestConfigurationIntegration:
    """Integration tests for the configuration system"""
    
    def test_auth_config_validation(self):
        settings = AiowsSettings(profile="development")
        settings.auth.enabled = True
        
        settings = AiowsSettings(profile="production")
        settings.auth.enabled = True
        assert settings.auth.secret_key is not None
    
    def test_ssl_configuration_warnings(self):
        settings = AiowsSettings(profile="production")
        
        settings.server.ssl_cert_file = "/path/to/cert.pem"
        settings.server.ssl_key_file = "/path/to/key.pem"
    
    def test_configuration_consistency(self):
        profiles = ["development", "production", "testing"]
        
        for profile in profiles:
            settings = AiowsSettings(profile=profile)
            
            assert settings.server.port > 0
            assert settings.server.shutdown_timeout > 0
            assert settings.rate_limit.max_messages_per_minute > 0
            assert settings.connection_limiter.max_connections_per_ip > 0
            
            if profile == "production":
                assert settings.server.is_production is True
                assert settings.logging.sanitize_data is True
            elif profile == "development":
                assert settings.server.is_production is False
                assert settings.logging.log_level == "DEBUG"
            elif profile == "testing":
                assert settings.server.port == 8001
                assert settings.logging.enable_rate_limiting is False


class TestConfigurationEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_circular_dependencies(self):
        class TestConfig(BaseConfig):
            value1 = ConfigValue(default="test1")
            value2 = ConfigValue(default="test2")
        
        config = TestConfig()
        assert config.value1 == "test1"
        assert config.value2 == "test2"
    
    def test_invalid_type_casting(self):
        with mock.patch.dict(os.environ, {'AIOWS_INVALID_INT': 'not_an_int'}):
            class TestConfig(BaseConfig):
                invalid_int = ConfigValue(default=0, type_cast=int)
            
            with pytest.raises(ConfigValidationError, match="Failed to cast"):
                TestConfig()
    
    def test_memory_efficiency(self):
        configs = [AiowsSettings() for _ in range(10)]
        
        for config in configs:
            assert config.server.host == "localhost"
            assert config.profile == "development"
    
    def test_thread_safety_basic(self):
        import threading
        
        settings = AiowsSettings()
        results = []
        
        def worker():
            results.append(settings.server.host)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(r == "localhost" for r in results)
        assert len(results) == 10 