"""
File: config/schema.py

Description:
    Loads the application schemas.

Author: Emfour Solutions
Created: 2025-07-05
"""

# Standard library imports
from dataclasses import dataclass, field
from enum import Enum

# Third-party imports
from typing import Any, Dict, List, Optional


class LogLevel(Enum):
    """Valid log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DatabaseType(Enum):
    """Supported database types."""

    SQLITE = "sqlite"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"


@dataclass
class DatabaseConfig:
    """Database configuration schema."""

    type: DatabaseType = DatabaseType.SQLITE
    track_modifications: bool = False
    record_queries: bool = False

    # Engine options
    pool_size: int = 20
    max_overflow: int = 30
    pool_timeout: int = 30
    pool_recycle: int = 3600
    pool_pre_ping: bool = True

    # Connection options
    connect_timeout: int = 60
    read_timeout: int = 30
    write_timeout: int = 30

    # Session options
    autoflush: bool = True
    autocommit: bool = False
    expire_on_commit: bool = True


@dataclass
class AppConfig:
    """Application configuration schema."""

    # Stream management
    default_poll_interval: int = 120
    max_concurrent_streams: int = 50

    # HTTP client settings
    http_timeout: int = 30
    http_max_connections: int = 100
    http_max_connections_per_host: int = 10

    # General settings
    async_timeout: int = 60
    max_worker_threads: int = 4

    # Feature flags
    enable_metrics: bool = True
    enable_health_checks: bool = True
    enable_debug_endpoints: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration schema."""

    level: LogLevel = LogLevel.INFO
    directory: str = "logs"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # File logging
    enable_file_logging: bool = True
    enable_console_logging: bool = True

    # Performance logging
    enable_sql_logging: bool = False
    enable_request_logging: bool = True


@dataclass
class SecurityConfig:
    """Security configuration schema."""

    secret_key: str = ""
    session_timeout: int = 3600  # 1 hour
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30

    # SSL/TLS settings
    require_ssl: bool = False
    ssl_cert_file: Optional[str] = None
    ssl_key_file: Optional[str] = None

    # CORS settings
    cors_origins: List[str] = field(default_factory=list)
    cors_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE"]
    )


@dataclass
class APIConfig:
    """API configuration schema."""

    # Rate limiting
    rate_limiting_enabled: bool = True
    default_rate: str = "100/hour"
    burst_rate: str = "10/minute"

    # Pagination
    default_page_size: int = 20
    max_page_size: int = 100

    # Authentication
    require_auth: bool = False
    auth_timeout: int = 3600  # 1 hour


@dataclass
class CompleteConfig:
    """Complete configuration schema."""

    environment: str = "development"
    debug: bool = False
    testing: bool = False

    # Core configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    app: AppConfig = field(default_factory=AppConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    api: APIConfig = field(default_factory=APIConfig)

    # Environment-specific overrides
    environment_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# Configuration validation schemas
CONFIG_SCHEMAS = {
    "database": {
        "type": {"type": "string", "enum": ["sqlite", "mysql", "postgresql"]},
        "track_modifications": {"type": "boolean"},
        "record_queries": {"type": "boolean"},
        "pool_size": {"type": "integer", "minimum": 1, "maximum": 100},
        "max_overflow": {"type": "integer", "minimum": 0, "maximum": 200},
        "pool_timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        "pool_recycle": {"type": "integer", "minimum": 60, "maximum": 7200},
        "pool_pre_ping": {"type": "boolean"},
        "connect_timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        "read_timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        "write_timeout": {"type": "integer", "minimum": 1, "maximum": 300},
    },
    "app": {
        "default_poll_interval": {"type": "integer", "minimum": 1, "maximum": 3600},
        "max_concurrent_streams": {"type": "integer", "minimum": 1, "maximum": 1000},
        "http_timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        "http_max_connections": {"type": "integer", "minimum": 1, "maximum": 1000},
        "http_max_connections_per_host": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        },
        "async_timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
        "max_worker_threads": {"type": "integer", "minimum": 1, "maximum": 100},
        "enable_metrics": {"type": "boolean"},
        "enable_health_checks": {"type": "boolean"},
        "enable_debug_endpoints": {"type": "boolean"},
    },
    "logging": {
        "level": {
            "type": "string",
            "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        },
        "directory": {"type": "string"},
        "max_file_size": {
            "type": "integer",
            "minimum": 1024,
            "maximum": 100 * 1024 * 1024,
        },
        "backup_count": {"type": "integer", "minimum": 0, "maximum": 50},
        "format": {"type": "string"},
        "enable_file_logging": {"type": "boolean"},
        "enable_console_logging": {"type": "boolean"},
        "enable_sql_logging": {"type": "boolean"},
        "enable_request_logging": {"type": "boolean"},
    },
    "security": {
        "secret_key": {"type": "string", "minLength": 16},
        "session_timeout": {"type": "integer", "minimum": 60, "maximum": 86400},
        "max_login_attempts": {"type": "integer", "minimum": 1, "maximum": 20},
        "lockout_duration_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
        "require_ssl": {"type": "boolean"},
        "ssl_cert_file": {"type": "string"},
        "ssl_key_file": {"type": "string"},
        "cors_origins": {"type": "array", "items": {"type": "string"}},
        "cors_methods": {"type": "array", "items": {"type": "string"}},
    },
    "api": {
        "rate_limiting_enabled": {"type": "boolean"},
        "default_rate": {
            "type": "string",
            "pattern": r"^\d+/(second|minute|hour|day)$",
        },
        "burst_rate": {"type": "string", "pattern": r"^\d+/(second|minute|hour|day)$"},
        "default_page_size": {"type": "integer", "minimum": 1, "maximum": 1000},
        "max_page_size": {"type": "integer", "minimum": 1, "maximum": 1000},
        "require_auth": {"type": "boolean"},
        "auth_timeout": {"type": "integer", "minimum": 60, "maximum": 86400},
    },
}


def get_config_documentation() -> Dict[str, Any]:
    """Get comprehensive configuration documentation."""
    return {
        "overview": {
            "description": "TrakBridge Configuration System",
            "version": "1.0.0",
            "environments": ["development", "production", "testing", "staging"],
        },
        "database": {
            "description": "Database configuration settings",
            "fields": {
                "type": {
                    "description": "Database type to use",
                    "type": "string",
                    "enum": ["sqlite", "mysql", "postgresql"],
                    "default": "sqlite",
                    "required": False,
                },
                "pool_size": {
                    "description": "Number of database connections to maintain in the pool",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20,
                    "recommended": {"development": 5, "production": 50, "testing": 2},
                },
                "max_overflow": {
                    "description": "Maximum number of connections that can be created beyond pool_size",
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 200,
                    "default": 30,
                },
                "pool_timeout": {
                    "description": "Timeout for getting a connection from the pool (seconds)",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 300,
                    "default": 30,
                },
            },
        },
        "app": {
            "description": "Application-specific configuration",
            "fields": {
                "default_poll_interval": {
                    "description": "Default interval between data polls (seconds)",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3600,
                    "default": 120,
                },
                "max_concurrent_streams": {
                    "description": "Maximum number of streams that can run simultaneously",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 50,
                },
                "http_timeout": {
                    "description": "HTTP request timeout (seconds)",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 300,
                    "default": 30,
                },
                "max_worker_threads": {
                    "description": "Maximum number of worker threads",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 4,
                },
            },
        },
        "logging": {
            "description": "Logging configuration",
            "fields": {
                "level": {
                    "description": "Logging level",
                    "type": "string",
                    "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    "default": "INFO",
                },
                "directory": {
                    "description": "Directory for log files",
                    "type": "string",
                    "default": "logs",
                },
                "max_file_size": {
                    "description": "Maximum size of log files before rotation (bytes)",
                    "type": "integer",
                    "minimum": 1024,
                    "maximum": 100 * 1024 * 1024,
                    "default": 10 * 1024 * 1024,
                },
            },
        },
        "security": {
            "description": "Security-related configuration",
            "fields": {
                "secret_key": {
                    "description": "Secret key for session encryption and CSRF protection",
                    "type": "string",
                    "minLength": 16,
                    "required": True,
                    "sensitive": True,
                },
                "session_timeout": {
                    "description": "Session timeout in seconds",
                    "type": "integer",
                    "minimum": 60,
                    "maximum": 86400,
                    "default": 3600,
                },
            },
        },
        "api": {
            "description": "API configuration settings",
            "fields": {
                "rate_limiting_enabled": {
                    "description": "Enable API rate limiting",
                    "type": "boolean",
                    "default": True,
                },
                "default_rate": {
                    "description": "Default rate limit (e.g., '100/hour')",
                    "type": "string",
                    "pattern": r"^\d+/(second|minute|hour|day)$",
                    "default": "100/hour",
                },
                "default_page_size": {
                    "description": "Default number of items per page",
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 20,
                },
            },
        },
    }


def validate_config_against_schema(
    config: Dict[str, Any], schema: Dict[str, Any]
) -> List[str]:
    """Validate configuration against JSON schema."""
    errors = []

    # This is a simplified validation - in production, you might want to use
    # a proper JSON schema validation library like jsonschema

    for field_name, field_schema in schema.items():
        if field_name in config:
            value = config[field_name]

            # Type validation
            expected_type = field_schema.get("type")
            if expected_type == "integer" and not isinstance(value, int):
                errors.append(f"{field_name} must be an integer")
            elif expected_type == "boolean" and not isinstance(value, bool):
                errors.append(f"{field_name} must be a boolean")
            elif expected_type == "string" and not isinstance(value, str):
                errors.append(f"{field_name} must be a string")
            elif expected_type == "array" and not isinstance(value, list):
                errors.append(f"{field_name} must be an array")

            # Enum validation
            if "enum" in field_schema and value not in field_schema["enum"]:
                errors.append(
                    f"{field_name} must be one of: {', '.join(field_schema['enum'])}"
                )

            # Range validation
            if isinstance(value, int):
                if "minimum" in field_schema and value < field_schema["minimum"]:
                    errors.append(
                        f"{field_name} must be at least {field_schema['minimum']}"
                    )
                if "maximum" in field_schema and value > field_schema["maximum"]:
                    errors.append(
                        f"{field_name} must be at most {field_schema['maximum']}"
                    )

            # String length validation
            if isinstance(value, str):
                if (
                    "minLength" in field_schema
                    and len(value) < field_schema["minLength"]
                ):
                    errors.append(
                        f"{field_name} must be at least {field_schema['minLength']} characters"
                    )
                if (
                    "maxLength" in field_schema
                    and len(value) > field_schema["maxLength"]
                ):
                    errors.append(
                        f"{field_name} must be at most {field_schema['maxLength']} characters"
                    )

    return errors
