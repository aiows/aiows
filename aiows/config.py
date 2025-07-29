"""
Centralized configuration system for aiows framework
"""

import os
import time
import logging
from typing import Any, Dict, List, Optional, Union, Type, Callable
from pathlib import Path


logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    pass


class ConfigValue:
    def __init__(self, 
                 default: Any = None,
                 env_var: Optional[str] = None,
                 validator: Optional[Callable[[Any], bool]] = None,
                 type_cast: Optional[Type] = None,
                 description: str = "",
                 required: bool = False,
                 sensitive: bool = False):
        self.default = default
        self.env_var = env_var
        self.validator = validator
        self.type_cast = type_cast
        self.description = description
        self.required = required
        self.sensitive = sensitive
        self._name = None
    
    def __set_name__(self, owner, name):
        self._name = name
        if self.env_var is None:
            self.env_var = f"AIOWS_{name.upper()}"
    
    def __get__(self, instance, owner):
        if instance is None:
            return self
        
        cache_key = f"_cached_{self._name}"
        if hasattr(instance, cache_key):
            return getattr(instance, cache_key)
        
        value = self._get_value()
        
        validated_value = self._validate_and_cast(value)
        setattr(instance, cache_key, validated_value)
        return validated_value
    
    def __set__(self, instance, value):
        validated_value = self._validate_and_cast(value)
        cache_key = f"_cached_{self._name}"
        setattr(instance, cache_key, validated_value)
    
    def _get_value(self) -> Any:
        env_value = os.getenv(self.env_var)
        if env_value is not None:
            return env_value
        
        if self.required and self.default is None:
            raise ConfigValidationError(
                f"Required configuration '{self._name}' not found. "
                f"Set environment variable '{self.env_var}' or provide default value."
            )
        
        return self.default
    
    def _validate_and_cast(self, value: Any) -> Any:
        if value is None and not self.required:
            return self.default
        
        if self.type_cast and value is not None:
            try:
                if self.type_cast == bool and isinstance(value, str):
                    value = value.lower() in ('true', '1', 'yes', 'on', 'enabled')
                elif self.type_cast == list and isinstance(value, str):
                    value = [item.strip() for item in value.split(',') if item.strip()]
                else:
                    value = self.type_cast(value)
            except (ValueError, TypeError) as e:
                raise ConfigValidationError(
                    f"Failed to cast '{self._name}' to {self.type_cast.__name__}: {e}"
                )
        
        if self.validator and not self.validator(value):
            raise ConfigValidationError(
                f"Validation failed for '{self._name}' with value: {value}"
            )
        
        return value
    
    def clear_cache(self, instance):
        cache_key = f"_cached_{self._name}"
        if hasattr(instance, cache_key):
            delattr(instance, cache_key)


class ConfigMeta(type):
    def __new__(cls, name, bases, namespace, **kwargs):
        config_values = {}
        for key, value in namespace.items():
            if isinstance(value, ConfigValue):
                config_values[key] = value
        
        namespace['_config_values'] = config_values
        
        return super().__new__(cls, name, bases, namespace)


class BaseConfig(metaclass=ConfigMeta):
    def __init__(self):
        self._config_values: Dict[str, ConfigValue] = getattr(self.__class__, '_config_values', {})
        self._load_timestamp = time.time()
        self._validation_errors: List[str] = []
        
        self.validate()
    
    def validate(self) -> None:
        self._validation_errors.clear()
        
        for name, config_value in self._config_values.items():
            try:
                getattr(self, name)
            except ConfigValidationError as e:
                self._validation_errors.append(str(e))
        
        if self._validation_errors:
            raise ConfigValidationError(
                f"Configuration validation failed:\n" + 
                "\n".join(f"  - {error}" for error in self._validation_errors)
            )
    
    def reload(self) -> None:
        logger.info("Reloading configuration from environment variables")
        
        for name, config_value in self._config_values.items():
            config_value.clear_cache(self)
        
        self._load_timestamp = time.time()
        
        self.validate()
        
        logger.info("Configuration reloaded successfully")
    
    def get_config_info(self) -> Dict[str, Any]:
        info = {
            'load_timestamp': self._load_timestamp,
            'validation_errors': self._validation_errors.copy(),
            'values': {}
        }
        
        for name, config_value in self._config_values.items():
            value = getattr(self, name)
            info['values'][name] = {
                'value': '***HIDDEN***' if config_value.sensitive else value,
                'env_var': config_value.env_var,
                'description': config_value.description,
                'required': config_value.required,
                'sensitive': config_value.sensitive,
                'type': type(value).__name__ if value is not None else 'None'
            }
        
        return info
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        result = {}
        for name, config_value in self._config_values.items():
            if config_value.sensitive and not include_sensitive:
                result[name] = '***HIDDEN***'
            else:
                result[name] = getattr(self, name)
        return result
    
    def update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        for name, value in config_dict.items():
            if name in self._config_values:
                setattr(self, name, value)
            else:
                logger.warning(f"Unknown configuration key: {name}")
    
    def get_env_vars(self) -> Dict[str, str]:
        return {name: config_value.env_var for name, config_value in self._config_values.items()}
    
    def export_env_template(self, file_path: Optional[Path] = None) -> str:
        lines = [
            "# aiows Configuration Environment Variables",
            "# Generated configuration template",
            f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        
        for name, config_value in self._config_values.items():
            lines.append(f"# {config_value.description}")
            if config_value.required:
                lines.append(f"# REQUIRED")
            else:
                lines.append(f"# Default: {config_value.default}")
            
            current_value = getattr(self, name)
            if config_value.sensitive:
                lines.append(f"{config_value.env_var}=***CHANGE_ME***")
            else:
                lines.append(f"{config_value.env_var}={current_value}")
            lines.append("")
        
        template = "\n".join(lines)
        
        if file_path:
            file_path.write_text(template)
            logger.info(f"Environment template exported to {file_path}")
        
        return template


def positive_number(value: Union[int, float]) -> bool:
    return isinstance(value, (int, float)) and value > 0


def positive_int(value: int) -> bool:
    return isinstance(value, int) and value > 0


def non_negative_number(value: Union[int, float]) -> bool:
    return isinstance(value, (int, float)) and value >= 0


def valid_port(value: int) -> bool:
    return isinstance(value, int) and 1 <= value <= 65535


def valid_host(value: str) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def non_empty_string(value: str) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def valid_log_level(value: str) -> bool:
    valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
    return isinstance(value, str) and value.upper() in valid_levels


def min_length(min_len: int) -> Callable[[str], bool]:
    def validator(value: str) -> bool:
        return isinstance(value, str) and len(value) >= min_len
    return validator


def in_range(min_val: Union[int, float], max_val: Union[int, float]) -> Callable[[Union[int, float]], bool]:
    def validator(value: Union[int, float]) -> bool:
        return isinstance(value, (int, float)) and min_val <= value <= max_val
    return validator


def in_choices(choices: List[Any]) -> Callable[[Any], bool]:
    def validator(value: Any) -> bool:
        return value in choices
    return validator 