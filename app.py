"""
TAK Stream Management System - Main Application Entry Point

Main Flask application factory providing multi-threaded stream management,
TAK server integration, and plugin architecture for data processing workflows.

Features: Application factory pattern, stream lifecycle management, database
integration, plugin system, encryption services, and deployment.

Author: Emfour Solutions
Created: 18-Jul-2025
License: Apache License 2.0 (Apache-2.0)
"""

# Standard library imports
import atexit
import logging
import os
import signal
import sys
import tempfile
import threading
import time
from datetime import datetime as dt
from pathlib import Path
from typing import Optional

# Third-party imports
from dotenv import load_dotenv
from flask import Flask, has_app_context, jsonify, render_template, request
from flask_migrate import Migrate
from sqlalchemy import event
from sqlalchemy.pool import Pool

# Load environment variables FIRST before any imports that need them
load_dotenv()

# Local application imports
from config.environments import get_config
from database import db
from services.cli.version_commands import register_version_commands
from services.logging_service import setup_logging
from services.stream_manager import StreamManager
from services.version import get_version, is_development_build

# Initialize extensions
migrate = Migrate()

# Global reference to stream manager for cleanup
_stream_manager_ref: Optional["StreamManager"] = None

# Global reference for startup splash screen
_startup_complete = False
_startup_error = None
_startup_progress = []

# Global flags to prevent duplicate startup - UPDATED
_startup_thread_started = False

# Set up logger
logger = logging.getLogger("main")


def set_startup_complete(success=True, error=None):
    """Mark startup as complete"""
    global _startup_complete, _startup_error
    _startup_complete = True
    _startup_error = error if not success else None


def add_startup_progress(message):
    """Add a progress message to startup log"""
    global _startup_progress
    _startup_progress.append({"timestamp": dt.now().isoformat(), "message": message})
    # Keep only last 20 messages
    if len(_startup_progress) > 20:
        _startup_progress = _startup_progress[-20:]


def get_startup_status():
    """Get current startup status"""
    return {
        "complete": _startup_complete,
        "error": _startup_error,
        "progress": _startup_progress,
    }


def initialize_database_safely():
    """
    Initialize database with proper migration handling.
    Handles both first-time setup and existing installations without conflicts.
    """
    import os

    from flask_migrate import current, stamp, upgrade

    from utils.database_error_formatter import (
        create_database_exception,
        log_database_error,
    )

    try:
        # Check if migrations directory exists
        migrations_dir = os.path.join(os.getcwd(), "migrations")
        if not os.path.exists(migrations_dir):
            logger.info(
                "No migrations directory found - creating database tables directly"
            )
            db.create_all()
            return

        # Check if database has migration version tracking
        try:
            current_revision = current()

            if current_revision is None:
                # Database exists but no migration version tracked
                inspector = db.inspect(db.engine)
                existing_tables = inspector.get_table_names()

                if existing_tables:
                    logger.info(f"Found existing tables: {existing_tables}")
                    # Stamp database with current migration version (don't run migrations)
                    try:
                        stamp()
                        logger.info("Database stamped with current migration version")
                    except Exception as stamp_error:
                        logger.warning(f"Could not stamp database: {stamp_error}")
                        logger.info("Database tables already exist, skipping creation")
                else:
                    # No tables exist - run migrations
                    logger.info("No tables found - running initial migration")
                    upgrade()
            else:
                # Database is under migration control - run upgrade if needed
                logger.info(f"Current migration revision: {current_revision}")
                logger.info("Running database upgrade (if needed)...")
                upgrade()

        except Exception as migration_error:
            logger.warning(f"Migration system not available: {migration_error}")
            # Fall back to direct table creation only if no tables exist
            try:
                inspector = db.inspect(db.engine)
                existing_tables = inspector.get_table_names()

                if not existing_tables:
                    logger.info(
                        "No tables found and migrations unavailable - creating tables directly"
                    )
                    db.create_all()
                else:
                    logger.info("Tables exist, skipping database initialization")

            except Exception as fallback_error:
                # Use enhanced error handling for database connection issues
                log_database_error(fallback_error, "Database table creation")
                db_error = create_database_exception(fallback_error)
                logger.error(f"Database initialization failed: {db_error}")
                raise db_error

    except Exception as e:
        # Enhanced error handling for database initialization
        if hasattr(e, "troubleshooting_steps"):
            # Already a formatted database error, re-raise as is
            raise
        else:
            # Convert raw exception to user-friendly database error
            log_database_error(e, "Database initialization")
            db_error = create_database_exception(e)
            logger.error(f"Database initialization failed: {db_error}")
            raise db_error


def log_full_startup_info(app):
    """Log comprehensive startup information for the primary process"""
    try:
        from services.logging_service import log_primary_startup_banner
        from services.version import format_version, get_build_info, get_version_info

        # Log startup banner
        log_primary_startup_banner(app)

        # Log detailed version information
        version_info = get_version_info()
        build_info = get_build_info()

        app.logger.info("=" * 60)
        app.logger.info("VERSION INFORMATION")
        app.logger.info("=" * 60)
        app.logger.info(f"Application: {format_version(include_build_info=True)}")
        app.logger.info(f"Version: {version_info.get('version', 'unknown')}")
        app.logger.info(f"Version Source: {version_info.get('source', 'unknown')}")
        app.logger.info(
            f"Development Build: {'YES' if is_development_build() else 'NO'}"
        )

        if build_info.get("git_commit"):
            app.logger.info(f"Git Commit: {build_info['git_commit']}")

        app.logger.info(
            f"Python Version: {version_info.get('environment', {}).get('python_version', 'unknown')}"
        )
        app.logger.info(
            f"Platform: {version_info.get('environment', {}).get('platform', 'unknown')}"
        )
        app.logger.info(f"Process ID: {os.getpid()}")
        app.logger.info(f"Working Directory: {os.getcwd()}")
        app.logger.info("=" * 60)

    except Exception as e:
        app.logger.warning(f"Could not log detailed version info: {e}")
        # Fallback to basic logging
        try:
            from services.version import format_version

            app.logger.info(f"Starting {format_version(include_build_info=True)}")
        except Exception as fallback_e:
            app.logger.warning(f"Could not log even basic version info: {fallback_e}")


def log_simple_worker_init(app):
    """Log simple initialization message for worker processes"""
    from services.logging_service import log_worker_initialization

    log_worker_initialization(app)


def is_hypercorn_environment() -> bool:
    """
    Detect if we're running under Hypercorn ASGI server.
    Hypercorn has its own worker management, so we don't need coordination.
    """
    return (
        # Check environment variables set by docker-compose or entrypoint
        os.environ.get("HYPERCORN_WORKERS") is not None
        or
        # Check command line arguments
        any("hypercorn" in arg for arg in sys.argv)
        or
        # Check server software environment variable
        os.environ.get("SERVER_SOFTWARE", "").startswith("hypercorn")
    )


def should_run_delayed_startup() -> bool:
    """
    Determine if this process should run the delayed startup tasks.
    For single worker deployment, always run startup tasks.
    """
    # Skip delayed startup in testing environment to prevent race conditions
    try:
        from flask import current_app

        if hasattr(current_app, "config") and current_app.config.get("TESTING", False):
            logger.debug("Testing environment detected - skipping delayed startup")
            return False
    except RuntimeError:
        # No application context available, continue with normal logic
        pass

    # Single worker deployment - always run startup tasks
    if is_hypercorn_environment():
        logger.debug("Single worker hypercorn deployment - running startup tasks")
        return True

    # Default to true for single worker deployment
    logger.debug("Single worker deployment - running startup tasks")
    return True


def _should_log_ready_banner() -> bool:
    """
    For single worker deployment, always log the ready banner.
    """
    return True


# Coordination functions removed for single worker deployment


def _is_container_shutdown() -> bool:
    """Check if we're in a container-managed shutdown scenario"""
    return os.getenv("CONTAINER_MANAGED", "").lower() == "true"


def create_app(config_name=None):
    global _stream_manager_ref

    app = Flask(__name__)

    # Determine environment and get configuration FIRST
    # (needed to check proxy settings before applying ProxyFix)
    flask_env = config_name or os.environ.get("FLASK_ENV", "development")
    config_instance = get_config(flask_env)

    # Load the API-key pepper before anything can generate or verify a
    # key. Refuses to boot in production when API_KEY_PEPPER is unset;
    # in dev/testing generates an ephemeral pepper with a WARNING.
    from services.auth.pepper import load_pepper
    load_pepper(is_production=(flask_env == "production"))

    # Configure reverse proxy support ONLY if explicitly trusted
    # This fixes redirect issues when behind reverse proxies while maintaining security
    proxy_trusted = getattr(config_instance, "PROXY_TRUSTED", False)
    if proxy_trusted:
        from werkzeug.middleware.proxy_fix import ProxyFix

        proxy_count = getattr(config_instance, "TRUSTED_PROXY_COUNT", 1)
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_count,  # Trust N proxies for X-Forwarded-For
            x_proto=proxy_count,  # Trust N proxies for X-Forwarded-Proto
            x_host=proxy_count,  # Trust N proxies for X-Forwarded-Host
            x_port=proxy_count,  # Trust N proxies for X-Forwarded-Port
            x_prefix=proxy_count,  # Trust N proxies for X-Forwarded-Prefix
        )
        logger.info(f"ProxyFix enabled: trusting {proxy_count} proxy(ies)")
    else:
        logger.info("ProxyFix disabled: using direct connection IPs")

    def app_context_factory():
        return app.app_context()

    # Store the factory on the app for easy access
    app.app_context_factory = app_context_factory
    app.config["SKIP_DB_INIT"] = (
        os.environ.get("SKIP_DB_INIT", "false").lower() == "true"
    )

    # config_instance already loaded above for ProxyFix configuration

    # Configure Flask app with the new configuration system
    configure_flask_app(app, config_instance)

    # Initialize extensions with app
    try:
        db.init_app(app)
        migrate.init_app(app, db)

        # Initialize CSRF protection globally
        from flask_wtf.csrf import CSRFProtect

        # CSRF is ON by default for all state-changing routes.
        # Bearer-authenticated and unauthenticated utility routes are exempted
        # individually below after blueprint registration.
        csrf = CSRFProtect()
        csrf.init_app(app)

        # Store CSRF instance
        app.csrf = csrf

        # ----- CSRF bearer-bypass hook -----
        # Any request carrying an API-key bearer token skips CSRF
        # validation. Bearer auth is itself unforgeable-across-origins
        # (an attacker on evil.com cannot make the browser attach the
        # header), so the CSRF requirement is redundant for that path.
        # Session-authenticated requests to the same routes remain
        # protected because the header check runs per-request; only
        # requests that actually present a tb_pat_ bearer bypass.
        #
        # Rejected alternative: route-level `csrf.exempt(...)` would
        # strip CSRF from BOTH session and bearer calls to the same
        # endpoint, defeating the whole point for browser JS callers.
        # This hook lets a single URL support both auth flows with the
        # right protection profile applied to each.
        from models.user import API_KEY_TOKEN_PREFIX
        _orig_csrf_protect = csrf.protect

        def _csrf_protect_with_bearer_bypass(*args, **kwargs):
            # Flask-WTF 1.1 called this hook as
            # ``protect(apply_exemptions=True)``; 1.2 dropped the
            # kwarg. Accept and forward whatever the caller passes
            # so the shim works against both versions — otherwise
            # the mismatch surfaces as a 500 on every request.
            auth = request.headers.get("Authorization", "")
            if auth.startswith(f"Bearer {API_KEY_TOKEN_PREFIX}"):
                return
            return _orig_csrf_protect(*args, **kwargs)

        csrf.protect = _csrf_protect_with_bearer_bypass

        logger.info(
            "CSRF protection enabled globally; bearer-auth routes "
            "exempted below and tb_pat_ bearer requests bypass CSRF"
        )

        # Add security headers (production only)
        if config_instance.environment == "production":
            try:
                from flask_talisman import Talisman
            except ImportError:
                logger.warning(
                    "flask-talisman not installed. Security headers disabled. "
                    "Install with: pip install flask-talisman"
                )
                Talisman = None

            if Talisman:
                # Configure Content Security Policy
                csp = {
                    "default-src": ["'self'"],
                    "script-src": [
                        "'self'",
                        "'unsafe-inline'",  # Required for inline scripts
                        "https://cdn.jsdelivr.net",  # Bootstrap/Font CDN
                        "https://unpkg.com",  # Leaflet maps CDN
                    ],
                    "style-src": [
                        "'self'",
                        "'unsafe-inline'",  # Required for inline styles
                        "https://cdn.jsdelivr.net",
                        "https://fonts.googleapis.com",
                        "https://unpkg.com",  # Leaflet maps CDN
                    ],
                    "img-src": ["'self'", "data:", "https:"],
                    "font-src": [
                        "'self'",
                        "https://cdn.jsdelivr.net",
                        "https://fonts.gstatic.com",
                    ],
                    "connect-src": [
                        "'self'",
                        "https://unpkg.com",
                    ],  # unpkg for Leaflet source maps
                    "frame-ancestors": ["'none'"],  # Prevent clickjacking
                }

                # Determine if we should force HTTPS:
                # - If behind reverse proxy (nginx), it handles SSL termination
                # - User can explicitly disable via FORCE_HTTPS=false
                force_https_config = getattr(config_instance, "FORCE_HTTPS", True)
                force_https = force_https_config and not proxy_trusted

                Talisman(
                    app,
                    force_https=force_https,
                    strict_transport_security=True,
                    strict_transport_security_preload=True,
                    content_security_policy=csp,
                    frame_options="DENY",
                    referrer_policy="strict-origin-when-cross-origin",
                    feature_policy={
                        "geolocation": "'none'",
                        "microphone": "'none'",
                        "camera": "'none'",
                    },
                )

                if not force_https:
                    if not force_https_config:
                        logger.warning(
                            "HTTPS forcing disabled by FORCE_HTTPS=false. "
                            "This is NOT recommended for public deployments!"
                        )
                    elif proxy_trusted:
                        logger.info(
                            "HTTPS forcing disabled - reverse proxy handles SSL"
                        )
                logger.info(
                    f"Security headers enabled (Talisman, force_https={force_https})"
                )
        else:
            logger.info(
                f"Security headers disabled in {config_instance.environment} environment"
            )

    except Exception as db_init_error:
        from utils.database_error_formatter import (
            create_database_exception,
            log_database_error,
        )

        log_database_error(db_init_error, "Database extension initialization")
        db_error = create_database_exception(db_init_error)
        logger.error(f"Failed to initialize database extensions: {db_error}")
        raise db_error

    # Configure scoped sessions for thread safety
    with app.app_context():
        # Make sessions thread-local
        # db.session = scoped_session(db.session)

        # Import models AFTER db.init_app to avoid circular imports
        # Import them individually rather than through the __init__.py
        from models.stream import Stream  # noqa: F401
        from models.tak_server import TakServer  # noqa: F401
        from models.user import User, UserSession  # noqa: F401

        # Register models with SQLAlchemy - use checkfirst=True to avoid conflicts
        db.Model.metadata.create_all(bind=db.engine, checkfirst=True)

        # Initialize stream manager and attach to Flask app
        from services.stream_manager import StreamManager

        app.stream_manager = StreamManager(app_context_factory=app_context_factory)

        # Initialize plugin manager and attach to Flask app
        from plugins.plugin_manager import PluginManager

        app.plugin_manager = PluginManager()
        app.plugin_manager.load_plugins_from_directory()
        app.plugin_manager.load_external_plugins()

        # Reconcile the installed-plugin registry with the filesystem
        # (grandfathers manually placed plugins into whitelist + DB)
        try:
            with app.app_context():
                from services.plugin_admin_service import sync_plugin_registry

                sync_plugin_registry()
                app.plugin_manager.reload_plugin_config()
                app.plugin_manager.load_external_plugins()
        except Exception as e:
            logger.warning(f"Plugin registry sync failed (non-fatal): {e}")

        # Initialize encryption service and attach to Flask app
        from services.encryption_service import EncryptionService

        app.encryption_service = EncryptionService()

        # Initialize authentication system
        from services.auth import AuthenticationManager
        from services.auth.decorators import create_auth_context_processor

        # Get authentication configuration
        auth_config = config_instance.get_auth_config()
        app.auth_manager = AuthenticationManager(auth_config)

        # Add authentication context processor for templates
        auth_context_processor = create_auth_context_processor()
        app.context_processor(auth_context_processor)

        # Store global reference for cleanup
        _stream_manager_ref = app.stream_manager

    # Set up database event listeners
    setup_database_events()

    # Set up logging (only once per app instance)
    setup_logging(app)

    # Add version context processor (only once per app instance)
    setup_version_context_processor(app)

    # Register cleanup handlers
    setup_cleanup_handlers()

    # Register version CLI commands
    register_version_commands(app)

    # Initialize rate limiting
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["120 per minute"],
        storage_uri="memory://",
    )
    app.limiter = limiter

    # Register blueprints
    from routes.admin import bp as admin_bp
    from routes.admin_api_keys import bp as admin_api_keys_bp
    from routes.api import bp as api_bp
    from routes.api_keys import bp as api_keys_bp
    from routes.auth import bp as auth_bp
    from routes.cot_types import bp as cot_types_bp
    from routes.main import bp as main_bp
    from routes.streams import bp as streams_bp
    from routes.tak_servers import bp as tak_servers_bp
    from routes.inbound import bp as inbound_bp
    from routes.openapi import bp as openapi_bp
    from routes.plugin_admin import bp as plugin_admin_bp

    # Apply rate limits to specific route groups
    limiter.limit("30 per minute")(api_bp)
    limiter.limit("10 per minute")(auth_bp)
    limiter.limit("60 per minute")(inbound_bp)

    app.register_blueprint(main_bp)
    app.register_blueprint(streams_bp, url_prefix="/streams")
    app.register_blueprint(tak_servers_bp, url_prefix="/tak-servers")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(plugin_admin_bp, url_prefix="/admin/plugins")
    app.register_blueprint(cot_types_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_keys_bp, url_prefix="/auth/api-keys")
    app.register_blueprint(admin_api_keys_bp, url_prefix="/admin/api-keys")
    app.register_blueprint(inbound_bp, url_prefix="/api/inbound")
    app.register_blueprint(openapi_bp, url_prefix="/api")

    # Apply per-route CSRF exemptions for non-session-authenticated endpoints.
    # Every exemption names the auth mechanism that replaces CSRF protection.
    #
    # routes/inbound.py — webhook endpoints use bearer-token auth
    # (plugin.validate_inbound_request checks Authorization: Bearer header).
    app.csrf.exempt(app.view_functions["inbound.receive_inbound_data"])  # CSRF exempt: bearer-token authenticated via plugin.validate_inbound_request
    #
    # routes/api.py — coordinate conversion utilities use @optional_auth
    # (no session required; pure computation with no privileged state changes).
    app.csrf.exempt(app.view_functions["api.convert_latlon_to_mgrs"])    # CSRF exempt: optional-auth utility; no authenticated state change
    app.csrf.exempt(app.view_functions["api.convert_mgrs_to_latlon"])    # CSRF exempt: optional-auth utility; no authenticated state change
    #
    # routes/openapi.py — auth-gated as of the docs-auth change;
    # GET-only handlers so CSRF isn't invoked on them anyway. Any
    # bearer request bypasses CSRF via the app-level hook above.

    # Add context processors and error handlers
    setup_template_helpers(app)
    setup_error_handlers(app)

    # Splash screen routes
    setup_startup_routes(app)

    return app


def setup_version_context_processor(app):
    """Set up version context processor and after-request banner system."""

    # Set up simple banner logging for single worker deployment
    banner_logged = False

    @app.before_request
    def maybe_log_ready_banner():
        """Log application ready banner once per startup."""
        nonlocal banner_logged

        if not banner_logged:
            banner_logged = True  # Prevent re-entry

            # Use simple coordination for single worker
            if _should_log_ready_banner():
                _log_startup_banner()

    def _log_startup_banner():
        """Log the startup banner"""
        try:
            from services.logging_service import log_primary_startup_banner

            # Include system information
            log_primary_startup_banner(app)

            app.logger.info("Application fully operational and handling traffic")
            app.logger.info("=" * 80)

            # Banner logged for single worker deployment
        except Exception as e:
            app.logger.error(f"Failed to log startup banner: {e}")

    @app.context_processor
    def inject_version_info():
        """Inject version information into all templates."""
        try:
            from services.version import get_build_info, get_version_info

            version_info = get_version_info()
            get_build_info()  # Called for side effects, not stored

            # Create a simplified version object for templates
            app_version = {
                "version": version_info.get("version", "0.0.0"),
                "is_development": is_development_build(),
                "git_commit": version_info.get("git", {}).get("commit_short"),
                "python_version": (
                    f"{version_info['environment']['python_version_info'].major}."
                    f"{version_info['environment']['python_version_info'].minor}."
                    f"{version_info['environment']['python_version_info'].micro}"
                ),
                "platform": version_info.get("environment", {}).get(
                    "platform", "unknown"
                ),
                "source": version_info.get("source", "unknown"),
            }

            return dict(app_version=app_version)

        except Exception as e:
            # Fallback in case of any errors
            app.logger.warning(f"Failed to inject version info: {e}")
            return dict(
                app_version={
                    "version": "0.0.0",
                    "is_development": True,
                    "git_commit": None,
                    "python_version": "unknown",
                    "platform": "unknown",
                    "source": "error",
                }
            )

    @app.context_processor
    def inject_moment():
        """Inject moment function for date handling in templates."""

        class MomentWrapper:
            def format(self, fmt):
                return dt.now().strftime(fmt)

            def __call__(self):
                return self

        return dict(moment=MomentWrapper())


def configure_flask_app(app, config_instance):
    """Configure Flask app with the configuration system."""

    # Core Flask settings
    app.config["SECRET_KEY"] = config_instance.SECRET_KEY
    app.config["DEBUG"] = config_instance.DEBUG
    app.config["TESTING"] = config_instance.TESTING

    # SQLAlchemy settings
    app.config["SQLALCHEMY_DATABASE_URI"] = config_instance.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = (
        config_instance.SQLALCHEMY_TRACK_MODIFICATIONS
    )
    app.config["SQLALCHEMY_RECORD_QUERIES"] = config_instance.SQLALCHEMY_RECORD_QUERIES
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = config_instance.SQLALCHEMY_ENGINE_OPTIONS
    app.config["SQLALCHEMY_SESSION_OPTIONS"] = (
        config_instance.SQLALCHEMY_SESSION_OPTIONS
    )

    # Application-specific settings
    app.config["MAX_WORKER_THREADS"] = config_instance.MAX_WORKER_THREADS
    app.config["DEFAULT_POLL_INTERVAL"] = config_instance.DEFAULT_POLL_INTERVAL
    app.config["MAX_CONCURRENT_STREAMS"] = config_instance.MAX_CONCURRENT_STREAMS
    app.config["HTTP_TIMEOUT"] = config_instance.HTTP_TIMEOUT
    app.config["HTTP_MAX_CONNECTIONS"] = config_instance.HTTP_MAX_CONNECTIONS
    app.config["HTTP_MAX_CONNECTIONS_PER_HOST"] = (
        config_instance.HTTP_MAX_CONNECTIONS_PER_HOST
    )
    app.config["ASYNC_TIMEOUT"] = config_instance.ASYNC_TIMEOUT

    # Logging settings
    app.config["LOG_LEVEL"] = config_instance.LOG_LEVEL
    app.config["LOG_DIR"] = config_instance.LOG_DIR

    # Import Version
    app.config["VERSION"] = get_version()

    # Security settings
    app.config["PROXY_TRUSTED"] = getattr(config_instance, "PROXY_TRUSTED", False)
    app.config["TRUSTED_PROXY_COUNT"] = getattr(
        config_instance, "TRUSTED_PROXY_COUNT", 0
    )

    # Session cookie security flags — set explicitly rather than relying on Flask defaults.
    # HttpOnly and SameSite are unconditional; Secure defaults to on in production and
    # off elsewhere, with a bidirectional env-var override so operators can force it
    # either way (e.g. HTTPS in dev, or plain HTTP behind a non-TLS-terminating proxy).
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    _secure_override = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
    _is_production = config_instance.environment == "production"
    if _secure_override in ("1", "true", "yes"):
        session_cookie_secure = True
    elif _secure_override in ("0", "false", "no"):
        session_cookie_secure = False
    else:
        session_cookie_secure = _is_production
    app.config["SESSION_COOKIE_SECURE"] = session_cookie_secure
    if _is_production and not session_cookie_secure:
        logger.warning(
            "SESSION_COOKIE_SECURE explicitly disabled in production — "
            "session cookies will be sent over plain HTTP. Terminate TLS at "
            "a reverse proxy in front of TrakBridge for production deployments."
        )

    # Rate limiting — disabled in testing to prevent cross-test pollution
    app.config["RATELIMIT_ENABLED"] = getattr(
        config_instance, "RATELIMIT_ENABLED", True
    )

    # Global request size limit — backstop only; every upload route enforces
    # its own tighter cap (licence 16KB, certs 5MB, plugin packages 10MB)
    app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

    # Store the config instance for later use
    app.config_instance = config_instance

    # Log configuration info (only once)
    if not hasattr(configure_flask_app, "_config_logged"):
        configure_flask_app._config_logged = True
        logger.info(
            f"Configured Flask app for environment: {config_instance.environment}"
        )

        # Validate configuration
        issues = config_instance.validate_config()
        if issues:
            logger.warning(f"Configuration issues found: {issues}")


#            if config_instance.environment == "production":
#               raise ValueError(f"Configuration validation failed: {issues}")


def initialize_admin_user_if_needed():
    """Initialize admin user using bootstrap service"""
    try:
        from services.auth.bootstrap_service import initialize_admin_user

        logger.info("Checking if initial admin user creation is needed...")
        add_startup_progress("Checking if initial admin user creation is needed...")

        # Attempt to create initial admin user
        admin_user = initialize_admin_user()

        if admin_user:
            logger.warning("=" * 60)
            logger.warning("INITIAL ADMIN USER CREATED")
            logger.warning(f"Username: {admin_user.username}")
            logger.warning("⚠️  DEFAULT PASSWORD ASSIGNED - CHANGE ON FIRST LOGIN  ⚠️")
            logger.warning("⚠️  CHANGE PASSWORD ON FIRST LOGIN  ⚠️")
            logger.warning("=" * 60)

            add_startup_progress(
                f"✓ Initial admin user '{admin_user.username}' created"
            )
            add_startup_progress("⚠️  Default password must be changed on first login")
        else:
            logger.debug(
                "Initial admin user creation not needed - admin users already exist"
            )
            add_startup_progress("✓ Admin users already exist, bootstrap not needed")

    except Exception as e:
        logger.error(f"Error during admin user bootstrap: {e}")
        add_startup_progress(f"Error during admin user bootstrap: {e}")


def start_active_streams():
    """Start all active streams with enhanced logging and proper error handling."""
    from flask import current_app

    stream_manager = getattr(current_app, "stream_manager", None)
    if stream_manager is None:
        logger.error("Stream manager not initialized")
        add_startup_progress("Error: Stream manager not initialized")
        return

    from models.stream import Stream

    try:
        logger.info("Initializing stream startup process...")
        add_startup_progress("Initializing stream startup process...")

        # Wait for stream manager to be ready with longer timeout
        logger.info("Waiting for stream manager to be ready...")
        add_startup_progress("Waiting for stream manager to be ready...")
        max_wait = 200  # 20 seconds
        wait_count = 0

        while wait_count < max_wait:
            time.sleep(0.1)
            wait_count += 1
            if (
                hasattr(stream_manager, "_loop")
                and stream_manager.loop
                and stream_manager.loop.is_running()
                and hasattr(stream_manager, "session_manager")
                and stream_manager.session_manager
                and getattr(stream_manager.session_manager, "session", None)
            ):
                break

        if wait_count >= max_wait:
            logger.error("Stream manager not ready after extended wait")
            add_startup_progress("Error: Stream manager not ready after extended wait")
            return

        logger.info("Stream manager ready, fetching active streams")
        add_startup_progress("Stream manager ready, fetching active streams")

        # Fetch active streams with proper error handling
        try:
            active_streams = Stream.query.filter_by(is_active=True).all()
            logger.info(f"Found {len(active_streams)} active streams to start")
            add_startup_progress(f"Found {len(active_streams)} active streams to start")

            if active_streams:
                for stream in active_streams:
                    logger.info(
                        f"Stream {stream.id}: {stream.name} ({stream.plugin_type})"
                    )

        except Exception as db_e:
            try:
                logger.error(f"Failed to fetch active streams from database: {db_e}")
            except (ValueError, OSError):
                # Handle cases where logging files are closed during shutdown
                pass
            add_startup_progress(
                f"Error: Failed to fetch active streams from database: {db_e}"
            )
            return

        if not active_streams:
            logger.info("No active streams found to start")
            add_startup_progress("No active streams found to start")
            return

        # Start streams with better logging
        started_count = 0
        failed_count = 0

        for stream in active_streams:
            try:
                logger.info(f"Starting stream {stream.id} ({stream.name})...")
                add_startup_progress(f"Starting stream {stream.id} ({stream.name})...")

                # Add retry logic
                max_retries = 3
                retry_count = 0
                success = False

                while retry_count < max_retries and not success:
                    try:
                        success = stream_manager.start_stream_sync(stream.id)
                        if success:
                            logger.debug(
                                f"Successfully started stream {stream.id} ({stream.name})"
                            )
                            add_startup_progress(
                                f"Successfully started stream {stream.id} ({stream.name})"
                            )
                            # Clear any previous error
                            fresh_stream = db.session.get(Stream, stream.id)
                            fresh_stream.last_error = None
                            db.session.commit()
                            started_count += 1
                            break
                        else:
                            retry_count += 1
                            if retry_count < max_retries:
                                logger.warning(
                                    f"Failed to start stream {stream.id}, retrying ({retry_count}/{max_retries})"
                                )
                                add_startup_progress(
                                    f"Failed to start stream {stream.id}, retrying ({retry_count}/{max_retries})"
                                )
                                time.sleep(2)
                            else:
                                logger.error(
                                    f"Failed to start stream {stream.id} after {max_retries} attempts"
                                )
                                add_startup_progress(
                                    f"✗ Failed to start stream {stream.id} after {max_retries} attempts"
                                )
                                failed_count += 1

                    except Exception as start_e:
                        retry_count += 1
                        if retry_count < max_retries:
                            logger.warning(
                                f"Exception starting stream {stream.id}, "
                                f"retrying ({retry_count}/{max_retries}): {start_e}"
                            )
                            add_startup_progress(
                                f"Exception starting stream {stream.id}, "
                                f"retrying ({retry_count}/{max_retries}): {start_e}"
                            )
                            time.sleep(2)
                        else:
                            logger.error(
                                f"Exception starting stream {stream.id} after {max_retries} attempts: {start_e}"
                            )
                            add_startup_progress(
                                f"✗ Exception starting stream {stream.id} after {max_retries} attempts: {start_e}"
                            )
                            failed_count += 1

                # Update stream status if failed
                if not success:
                    try:
                        fresh_stream = Stream.query.get(stream.id)
                        if fresh_stream:
                            # Only mark inactive if NOT in container environment
                            if not _is_container_shutdown():
                                fresh_stream.is_active = False
                                fresh_stream.last_error = (
                                    "Failed to start during app startup"
                                )
                                db.session.commit()
                                logger.info(
                                    f"Marked stream {stream.id} as inactive due to startup failure"
                                )
                            else:
                                logger.info(
                                    f"Container environment detected - preserving active state for stream {stream.id}"
                                )
                    except Exception as db_e:
                        logger.error(
                            f"Failed to update stream {stream.id} status: {db_e}"
                        )
                        try:
                            db.session.rollback()
                        except Exception:
                            pass

                # Delay between starts
                time.sleep(3)

            except Exception as e:
                logger.error(
                    f"Unexpected error starting stream {stream.id}: {e}", exc_info=True
                )
                add_startup_progress(
                    f"✗ Unexpected error starting stream {stream.id}: {e}"
                )
                failed_count += 1

            # Log final results for single worker deployment
            logger.info("=" * 50)
            logger.info("Stream Startup Results:")
            logger.info(f"Started: {started_count}")
            logger.info(f" Failed: {failed_count}")
            logger.info(f"  Total: {len(active_streams)}")
            logger.info(
                f"Success Rate: {(started_count / len(active_streams) * 100):.1f}%"
            )
            logger.info("=" * 50)

        add_startup_progress(
            f"Stream startup complete: {started_count} started, {failed_count} failed"
        )

    except Exception as e:
        logger.error(f"Error in start_active_streams: {e}", exc_info=True)
        add_startup_progress(f"Error in start_active_streams: {e}")


def setup_database_events():
    """Set up database event listeners for better connection handling"""

    @event.listens_for(Pool, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        """Set SQLite pragmas for better performance and concurrency"""
        if "sqlite" in str(dbapi_conn):
            cursor = dbapi_conn.cursor()
            # Enable WAL mode for better concurrency
            cursor.execute("PRAGMA journal_mode=WAL")
            # Set busy timeout to 30 seconds
            cursor.execute("PRAGMA busy_timeout=30000")
            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys=ON")
            # Set synchronous mode for better performance
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    @event.listens_for(Pool, "checkout")
    def receive_checkout(dbapi_conn, connection_record, connection_proxy):
        """Log connection checkouts in debug mode"""
        logging.debug(f"Connection checked out: {id(dbapi_conn)}")

    @event.listens_for(Pool, "checkin")
    def receive_checkin(dbapi_conn, connection_record):
        """Log connection checkins in debug mode"""
        logging.debug(f"Connection checked in: {id(dbapi_conn)}")


def setup_cleanup_handlers():
    """Set up cleanup handlers for graceful shutdown"""

    def cleanup():
        """Clean up resources on application shutdown"""
        global _stream_manager_ref

        try:
            # Use global reference instead of current_app
            if _stream_manager_ref is not None:
                try:
                    _stream_manager_ref.shutdown()
                    logger.info("Stream manager shutdown completed")
                except Exception as e:
                    logger.error(f"Error during stream manager shutdown: {e}")
            else:
                logger.info("No stream manager reference available for cleanup")

            # Close database connections
            try:
                # Check if we have an active Flask application context
                if has_app_context():
                    db.session.remove()
                    db.engine.dispose()
                    logger.info("Database connections closed")
                else:
                    # Outside of application context, try direct engine disposal
                    if hasattr(db, "engine") and db.engine:
                        db.engine.dispose()
                        logger.info("Database engine disposed (outside app context)")
                    else:
                        logger.debug("No database engine available for cleanup")
            except Exception as e:
                logger.error(f"Error closing database connections: {e}")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        # Startup coordination resources cleanup removed for single worker

        logger.info("Application cleanup completed")

    def safe_stream_manager_shutdown():
        """Safely shutdown stream manager during application exit"""
        global _stream_manager_ref

        try:
            if _stream_manager_ref is not None:
                try:
                    _stream_manager_ref.shutdown()
                    logger.info("Stream manager shutdown completed via atexit")
                except Exception as e:
                    logger.error(f"Error during stream manager shutdown: {e}")
            else:
                logger.info("No stream manager reference available for atexit cleanup")
        except Exception as e:
            logger.error(f"Error during stream manager shutdown: {e}")

        # Startup coordination resources cleanup removed for single worker

    # Register cleanup handlers
    atexit.register(safe_stream_manager_shutdown)

    # For WSGI servers
    def cleanup_handler(signum, frame):
        cleanup()
        exit(0)

    signal.signal(signal.SIGTERM, cleanup_handler)
    signal.signal(signal.SIGINT, cleanup_handler)


def setup_template_helpers(app):
    """Add context processors for templates"""

    @app.context_processor
    def utility_processor():
        """Add utility functions to template context"""
        return dict(enumerate=enumerate, len=len, str=str)


def setup_error_handlers(app):
    """Set up error handlers"""

    # Import database exception classes
    from services.exceptions import (
        DatabaseAuthenticationError,
        DatabaseConfigurationError,
        DatabaseConnectionError,
        DatabaseError,
        DatabaseNotFoundError,
    )
    from utils.database_error_formatter import format_error_response

    @app.errorhandler(DatabaseConnectionError)
    def handle_database_connection_error(error):
        """Handle database connection errors"""
        logger.error(f"Database connection error: {error}")
        if hasattr(db, "session"):
            try:
                db.session.rollback()
            except Exception as e:
                logger.warning(
                    f"Failed to rollback database session: {e}"
                )  # Session may not be available

        error_response = format_error_response(error)
        return jsonify(error_response), 503

    @app.errorhandler(DatabaseAuthenticationError)
    def handle_database_auth_error(error):
        """Handle database authentication errors"""
        logger.error(f"Database authentication error: {error}")
        if hasattr(db, "session"):
            try:
                db.session.rollback()
            except Exception as e:
                logger.warning(f"Failed to rollback database session: {e}")

        error_response = format_error_response(error)
        return jsonify(error_response), 500

    @app.errorhandler(DatabaseNotFoundError)
    def handle_database_not_found_error(error):
        """Handle database/table not found errors"""
        logger.error(f"Database not found error: {error}")
        if hasattr(db, "session"):
            try:
                db.session.rollback()
            except Exception as e:
                logger.warning(f"Failed to rollback database session: {e}")

        error_response = format_error_response(error)
        return jsonify(error_response), 500

    @app.errorhandler(DatabaseConfigurationError)
    def handle_database_config_error(error):
        """Handle database configuration errors"""
        logger.error(f"Database configuration error: {error}")
        if hasattr(db, "session"):
            try:
                db.session.rollback()
            except Exception as e:
                logger.warning(f"Failed to rollback database session: {e}")

        error_response = format_error_response(error)
        return jsonify(error_response), 500

    @app.errorhandler(DatabaseError)
    def handle_generic_database_error(error):
        """Handle generic database errors"""
        logger.error(f"Database error: {error}")
        if hasattr(db, "session"):
            try:
                db.session.rollback()
            except Exception as e:
                logger.warning(f"Failed to rollback database session: {e}")

        error_response = format_error_response(error)
        return jsonify(error_response), 500

    from flask import request as _request
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        """Return 400 for CSRF validation failures with a clear error message."""
        logger.warning(f"CSRF validation failed: {error.description}")
        if _request.is_json or _request.content_type == "application/json":
            return jsonify({"error": "CSRF token missing or invalid"}), 400
        return "Bad Request: CSRF token missing or invalid", 400

    @app.errorhandler(400)
    def bad_request_error(error):
        """Return 400 for bad requests."""
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"500 error handler called with error: {error}", exc_info=True)
        try:
            db.session.rollback()
        except Exception as e:
            logger.warning(f"Failed to rollback session in 500 handler: {e}")
        try:
            response = render_template("errors/500.html"), 500
            return response
        except Exception as template_error:
            logger.error(
                f"Failed to render 500 template: {template_error}", exc_info=True
            )
            # Return a plain text response as fallback
            return "Internal Server Error", 500

    @app.errorhandler(503)
    def service_unavailable_error(error):
        try:
            db.session.rollback()
        except Exception as e:
            logger.warning(f"Failed to rollback session in 503 handler: {e}")
        return render_template("errors/503.html"), 503

    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Preserve HTTP-status exceptions (429, etc.) as their own response.

        Without this, the catch-all `handle_exception` below swallows
        `HTTPException` — Flask-Limiter's 429 was being converted into a
        500 "This page isn't working" error, hiding the real reason.

        Renders a friendly HTML template for browser callers when
        available; falls back to JSON for API clients or if no template
        exists.
        """
        # Log rate-limit hits at WARNING so operators see brute-force
        # signals. Other HTTP exceptions (404, 400, 405, ...) already
        # have dedicated handlers above or are not worth per-hit logging.
        if e.code == 429:
            logger.warning(
                f"Rate limit exceeded for {request.remote_addr} at "
                f"{request.endpoint}: {e.description}"
            )

        wants_json = (
            request.is_json
            or request.content_type == "application/json"
            or "application/json" in (request.headers.get("Accept") or "")
        )
        if wants_json:
            return (
                jsonify({"error": e.name, "description": e.description}),
                e.code,
            )

        template = f"errors/{e.code}.html"
        try:
            return render_template(template), e.code
        except Exception:
            # No template for this status — return the Werkzeug default.
            return e.get_response()

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle uncaught exceptions"""
        logging.error(f"Unhandled exception: {e}", exc_info=True)

        # Check if this is a raw database exception that should be converted
        exception_type = type(e).__name__
        exception_str = str(e).lower()

        if any(
            db_indicator in exception_str
            for db_indicator in [
                "psycopg2",
                "mysql",
                "sqlite",
                "sqlalchemy",
                "database",
                "connection",
            ]
        ) or any(
            db_type in exception_type.lower()
            for db_type in [
                "operational",
                "integrity",
                "programming",
                "data",
                "internal",
            ]
        ):
            # This looks like a database error - convert it to user-friendly format
            from utils.database_error_formatter import (
                create_database_exception,
                format_error_response,
            )

            try:
                db_error = create_database_exception(e)
                error_response = format_error_response(db_error)
                return jsonify(error_response), 500
            except Exception:
                # If conversion fails, fall through to generic handling
                pass

        try:
            db.session.rollback()
        except Exception as rollback_error:
            # Database session may not be available
            logger.warning(f"Failed to rollback database session: {rollback_error}")

        if app.debug:
            raise e

        return render_template("errors/500.html"), 500


def setup_startup_routes(app):
    """Set up startup-related routes"""

    @app.route("/startup-status")
    def startup_status():
        """API endpoint to check startup status"""
        return jsonify(get_startup_status())

    @app.route("/startup")
    def startup_page():
        """Display startup/loading page"""
        return render_template("startup.html")

    @app.before_request
    def check_startup():
        """Check if startup is complete before processing requests"""
        from flask import request

        # Allow startup-related routes and static files
        if request.endpoint in ["startup_page", "startup_status", "static"]:
            return None

        # Allow authentication routes
        if request.path.startswith("/auth/"):
            return None

        # Allow API health checks
        if request.path.startswith("/api/health"):
            return None

        # Skip startup check in testing environment
        if app.config.get("TESTING", False):
            return None

        # Redirect to startup page if not ready
        if not _startup_complete and request.endpoint:
            if request.is_json:
                return (
                    jsonify(
                        {
                            "status": "starting",
                            "message": "Application is starting up",
                        }
                    ),
                    503,
                )
            else:
                return render_template("startup.html")

        return None


# Create the application instance
# Always create app except when TESTING environment variable is set
if os.environ.get("TESTING") == "1":
    # For tests, don't create app at module level to avoid startup issues
    app = None
else:
    # For direct execution and server imports (like Hypercorn)
    app = create_app()

    # Phase 2: Register worker for startup coordination
    # This ensures individual workers register with the coordination service
    with app.app_context():
        log_simple_worker_init(app)


# Delayed startup function that runs in a separate thread
def safe_log(level_func, message):
    """Safe logging that handles closed log files during shutdown"""
    try:
        level_func(message)
    except (ValueError, OSError):
        # Handle cases where logging files are closed during shutdown
        pass


def delayed_startup():
    """
    Run startup tasks after Flask is fully initialized.
    Only runs in the primary process to prevent duplicate execution.
    """
    global _startup_complete, _startup_error

    # Check if we should run startup tasks
    if not should_run_delayed_startup():
        safe_log(
            logger.info, "Delayed startup tasks will be handled by another process"
        )
        return

    startup_start_time = dt.now()

    try:
        # Wait a bit for Flask to fully initialize
        add_startup_progress("Flask application initialized, starting services...")
        time.sleep(5)

        with app.app_context():
            safe_log(logger.debug, "Running delayed startup tasks (PRIMARY PROCESS)...")
            add_startup_progress("Checking system components...")

            # Log system status
            try:
                safe_log(logger.info, "System Status Check:")
                safe_log(
                    logger.info,
                    f"Stream Manager: {'Ready' if hasattr(app, 'stream_manager') else 'Not Ready'}",
                )
                safe_log(
                    logger.info,
                    f"Plugin Manager: {'Ready' if hasattr(app, 'plugin_manager') else 'Not Ready'}",
                )
                safe_log(
                    logger.info, f"Database: {'Ready' if db.engine else 'Not Ready'}"
                )
                safe_log(
                    logger.info,
                    f"Encryption Service: {'Ready' if hasattr(app, 'encryption_service') else 'Not Ready'}",
                )

                add_startup_progress("System components verified")
            except Exception as e:
                safe_log(logger.warning, f"Could not log system status: {e}")
                add_startup_progress(
                    f"Warning: Could not verify all system components: {e}"
                )

            # Initialize admin user if needed
            add_startup_progress("Checking admin user bootstrap...")
            initialize_admin_user_if_needed()

            # Start active streams
            add_startup_progress("Starting active streams...")
            start_active_streams()

            # Calculate startup time
            startup_time = (dt.now() - startup_start_time).total_seconds()

            # Startup completion will be logged by the coordinated banner system
            # No need to log duplicate startup messages here

            # Worker coordination registration removed - not needed for basic operation

            add_startup_progress(
                f"Startup complete! Ready in {startup_time:.2f} seconds"
            )
            set_startup_complete(True)

    except Exception as e:
        safe_log(logger.error, f"Error during startup: {e}")
        add_startup_progress(f"Startup failed: {str(e)}")
        set_startup_complete(False, str(e))


# Prevent duplicate startup thread creation
def ensure_startup_thread():
    """Ensure startup thread is only created once per process"""
    global _startup_thread_started

    # Skip startup thread during database migrations to avoid querying
    # columns that haven't been created yet by pending migrations
    if os.environ.get("TRAKBRIDGE_MIGRATION_MODE") == "1":
        logger.debug("Migration mode detected - skipping startup thread")
        return

    if not _startup_thread_started:
        _startup_thread_started = True

        # Run startup in a separate thread to avoid blocking Flask initialization
        startup_thread = threading.Thread(
            target=delayed_startup, daemon=True, name=f"StartupThread-{os.getpid()}"
        )
        startup_thread.start()
        logger.info(f"Startup thread initiated for PID {os.getpid()}")


# Only start the startup thread if running directly or in production
if __name__ == "__main__":
    ensure_startup_thread()

    # Initialize database safely within app context
    with app.app_context():
        initialize_database_safely()

    app.run(debug=False, port=8080, threaded=True)
elif app is not None:
    # For production/WSGI deployment (only if app was created)
    ensure_startup_thread()
