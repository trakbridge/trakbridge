"""
File: plugins/plugin_manager.py

Description:
    Manages discovery, loading, registration, and lifecycle of GPS tracking plugins.
    Supports plugin configuration, validation, metadata extraction, connection testing,
    runtime health checks, and dynamic reloading. Integrates with the stream model for
    system-wide plugin orchestration.

Author: Emfour Solutions
Created: 2025-07-05
"""

# Standard library imports
import hashlib
import importlib
import importlib.util
import inspect
import json
import logging
import os
import pkgutil
import sys
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type, Union

# Local imports for JSON validation
from utils.json_validator import JSONValidationError, safe_json_loads

# Third-party imports
# (none for this file)

# Local application imports
if TYPE_CHECKING:
    from plugins.base_plugin import BaseGPSPlugin, BaseInboundPlugin, BaseOutputPlugin

# Module-level logger
logger = logging.getLogger(__name__)


class PluginManager:
    """Enhanced manager for GPS tracking plugins with metadata support"""

    # Default built-in plugin modules (always allowed).
    # NOTE: external plugins are NOT blanket-allowed — each one requires an
    # explicit "external_plugins.<plugin_id>" entry in the whitelist
    # (allowed_plugin_modules in plugins.yaml), managed by the plugin admin UI.
    BUILTIN_PLUGIN_MODULES = {
        "plugins.garmin_plugin",
        "plugins.spot_plugin",
        "plugins.traccar_plugin",
        "plugins.deepstate_plugin",
        "plugins.liveuamap_plugin",
        "plugins",  # Allow the plugins package itself
    }

    def __init__(self):
        # Support GPS input plugins, output plugins, and inbound plugins
        self.plugins: Dict[
            str, Type[Union["BaseGPSPlugin", "BaseOutputPlugin", "BaseInboundPlugin"]]
        ] = {}
        self._allowed_modules = self.BUILTIN_PLUGIN_MODULES.copy()
        self._builtin_plugin_names: set = set()
        # V1/V2: sideloaded unsigned community-tier plugins are refused
        # by default. Operator opts in via
        # plugin_settings.allow_community_sideload in plugins.yaml.
        # Pro/enterprise plugins are never permitted unsigned, regardless
        # of this flag.
        self._allow_community_sideload: bool = False
        self._load_allowed_plugins_config()

    def _load_allowed_plugins_config(self):
        """
        Load additional allowed plugin modules from configuration files.
        This allows administrators to add new plugins without code changes.
        Uses safe configuration loading with validation and auto-repair.
        """
        try:
            from config.base import get_config_loader

            # Use safe configuration loading with validation and auto-repair
            config = get_config_loader().load_config_safe(
                "plugins.yaml", required_fields=["allowed_plugin_modules"]
            )

            if config and "allowed_plugin_modules" in config:
                additional_modules = config["allowed_plugin_modules"]
                # Handle None, empty lists, and actual lists gracefully
                if additional_modules is None or additional_modules == []:
                    logger.info(
                        "No additional plugin modules configured (using built-in plugins only)"
                    )
                elif isinstance(additional_modules, list):
                    modules_added = 0
                    for module in additional_modules:
                        if isinstance(module, str) and self._is_safe_module_name(
                            module
                        ):
                            self._allowed_modules.add(module)
                            logger.info(f"Added allowed plugin module: {module}")
                            modules_added += 1
                        else:
                            logger.warning(
                                f"Ignoring unsafe plugin module name: {module}"
                            )

                    logger.info(
                        f"Plugin configuration loaded successfully: {modules_added} modules added"
                    )
                else:
                    logger.warning(
                        "Plugin configuration 'allowed_plugin_modules' must be a list"
                    )
            else:
                logger.info(
                    "No additional plugin modules configured (using built-in plugins only)"
                )

            # V1/V2: read the sideload opt-in from plugin_settings.
            # Absent block or missing key → default False.
            plugin_settings = (config or {}).get("plugin_settings") or {}
            allow_sideload = bool(
                plugin_settings.get("allow_community_sideload", False)
            )
            self._allow_community_sideload = allow_sideload
            if allow_sideload:
                logger.warning(
                    "plugin_settings.allow_community_sideload=true — "
                    "unsigned community-tier plugins in external_plugins/ "
                    "will be loaded. Pro/enterprise plugins remain refused."
                )

        except Exception as e:
            # Graceful fallback - continue with built-in plugins only
            logger.warning(
                f"Failed to load plugin configuration, using built-in plugins only: {e}"
            )
            logger.info(
                "Application startup will continue with default built-in plugins"
            )

    def _is_safe_module_name(self, module_name: str) -> bool:
        """
        Validate that a module name follows safe patterns.
        This prevents malicious module names even in config files.
        """
        if not isinstance(module_name, str):
            return False

        # Must start with 'plugins.', 'external_plugins.', or be 'plugins'/'external_plugins'
        allowed_prefixes = [
            "plugins",
            "plugins.",
            "external_plugins",
            "external_plugins.",
        ]
        if not any(
            module_name == prefix.rstrip(".") or module_name.startswith(prefix)
            for prefix in allowed_prefixes
        ):
            return False

        # No path traversal or dangerous characters
        if any(char in module_name for char in ["..", "/", "\\", ";", "|", "&", "`"]):
            return False

        # Only alphanumeric, dots, and underscores
        if not all(c.isalnum() or c in "._" for c in module_name):
            return False

        return True

    def add_allowed_plugin_module(self, module_name: str) -> bool:
        """
        Dynamically add an allowed plugin module (for admin use).

        Args:
            module_name: The module name to allow

        Returns:
            bool: True if added successfully, False if rejected
        """
        if self._is_safe_module_name(module_name):
            self._allowed_modules.add(module_name)
            logger.info(f"Dynamically added allowed plugin module: {module_name}")
            return True
        else:
            logger.warning(f"Rejected unsafe plugin module name: {module_name}")
            return False

    def get_allowed_plugin_modules(self) -> List[str]:
        """
        Get the current list of allowed plugin modules.

        Returns:
            List of allowed module names
        """
        return sorted(list(self._allowed_modules))

    def reload_plugin_config(self):
        """
        Reload the plugin configuration from config files.
        This allows dynamic updates without restarting the application.
        """
        # Reset to built-in modules
        self._allowed_modules = self.BUILTIN_PLUGIN_MODULES.copy()
        # Reset sideload flag to default before re-reading
        self._allow_community_sideload = False
        # Reload from config files
        self._load_allowed_plugins_config()
        logger.info("Plugin configuration reloaded")

    def _load_external_plugins_directory(self, plugins_path: str):
        """
        Load plugins from external directory (e.g., Docker volume mount).
        Uses file-based loading instead of package imports to avoid namespace conflicts.
        Supports GPS input, output, and inbound plugins.
        """
        from plugins.base_plugin import (
            BaseGPSPlugin,
            BaseInboundPlugin,
            BaseOutputPlugin,
        )

        try:
            # Package-format plugins (subdirectories with plugin.yaml) first
            self._load_package_plugins(plugins_path)

            # Get all Python files in the external directory
            for filename in os.listdir(plugins_path):
                if (
                    filename.endswith(".py")
                    and not filename.startswith("__")
                    and filename != "base_plugin.py"
                ):
                    module_name = filename[:-3]  # Remove .py extension

                    # Create a module name for external plugins
                    external_module_name = f"external_plugins.{module_name}"

                    # Check if this external module is allowed
                    if not self._validate_module_name(external_module_name):
                        logger.warning(
                            f"External plugin {module_name} not in allowed list, skipping"
                        )
                        continue

                    # V1/V2 signature gate for loose .py sideloads.
                    # Loose files have no manifest → treated as
                    # community-tier for the toggle. Pro/enterprise
                    # plugins must be shipped as signed packages, not
                    # loose .py files.
                    from services.plugin_package_verifier import (
                        verify_single_file_signature,
                    )

                    py_full_path = Path(plugins_path) / filename
                    sig_status = verify_single_file_signature(py_full_path)
                    if sig_status != "verified":
                        if self._allow_community_sideload:
                            logger.warning(
                                f"Loading UNSIGNED sideloaded plugin "
                                f"'{filename}' (signature status: "
                                f"{sig_status}). "
                                "allow_community_sideload=true — this "
                                "file is trusted only because the "
                                "operator opted in."
                            )
                        else:
                            logger.warning(
                                f"Skipping sideloaded plugin "
                                f"'{filename}': signature status "
                                f"{sig_status}. Set "
                                "plugin_settings.allow_community_sideload"
                                "=true in config/settings/plugins.yaml "
                                "to allow unsigned community-tier "
                                "sideload."
                            )
                            continue

                    try:
                        # Import the module using spec loading
                        spec = importlib.util.spec_from_file_location(
                            external_module_name, os.path.join(plugins_path, filename)
                        )

                        if spec is None or spec.loader is None:
                            logger.error(
                                f"Failed to create spec for external plugin: {filename}"
                            )
                            continue

                        module = importlib.util.module_from_spec(spec)

                        # Add to sys.modules to avoid import issues
                        sys.modules[external_module_name] = module
                        spec.loader.exec_module(module)

                        # Look for plugin classes (GPS, output, and inbound plugins)
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            # Check if it's a GPS plugin
                            if (
                                issubclass(obj, BaseGPSPlugin)
                                and obj is not BaseGPSPlugin
                            ):
                                logger.info(
                                    f"Loading external GPS plugin: {name} from {filename}"
                                )
                                self.register_plugin(obj)
                            # Check if it's an output plugin
                            elif (
                                issubclass(obj, BaseOutputPlugin)
                                and obj is not BaseOutputPlugin
                            ):
                                logger.info(
                                    f"Loading external output plugin: {name} from {filename}"
                                )
                                self.register_plugin(obj)
                            # Check if it's an inbound plugin
                            elif (
                                issubclass(obj, BaseInboundPlugin)
                                and obj is not BaseInboundPlugin
                            ):
                                logger.info(
                                    f"Loading external inbound plugin: {name} from {filename}"
                                )
                                self.register_plugin(obj)

                    except Exception as e:
                        logger.error(
                            f"Failed to load external plugin file {filename}: {e}"
                        )

        except Exception as e:
            logger.error(
                f"Failed to scan external plugins directory {plugins_path}: {e}"
            )

    def _load_package_plugins(self, plugins_path: str):
        """
        Load package-format plugins: subdirectories containing a plugin.yaml
        manifest. Enforces the whitelist, the manifest-id/directory-name
        identity rule, entry-point containment, and the licence tier gate
        (so file-copy sideloading cannot bypass tier enforcement).
        """
        import yaml

        from plugins.base_plugin import (
            BaseGPSPlugin,
            BaseInboundPlugin,
            BaseOutputPlugin,
        )

        base_path = os.path.abspath(plugins_path)
        try:
            entries = sorted(os.listdir(base_path))
        except OSError as e:
            logger.error(f"Failed to scan package plugins directory {base_path}: {e}")
            return

        for entry in entries:
            package_dir = os.path.join(base_path, entry)
            if not os.path.isdir(package_dir) or entry.startswith("__"):
                continue
            manifest_path = os.path.join(package_dir, "plugin.yaml")
            if not os.path.isfile(manifest_path):
                continue

            try:
                with open(manifest_path, "r") as f:
                    manifest = yaml.safe_load(f) or {}

                plugin_id = manifest.get("id")
                if plugin_id != entry:
                    logger.warning(
                        f"Skipping package plugin '{entry}': manifest id "
                        f"'{plugin_id}' does not match directory name"
                    )
                    continue

                module_name = f"external_plugins.{plugin_id}"
                if not self._validate_module_name(module_name):
                    logger.warning(
                        f"Package plugin '{plugin_id}' not in allowed list, skipping"
                    )
                    continue

                # Tier gate: sideloaded premium packages must not load below
                # their declared tier
                tier = manifest.get("tier", "community")
                from services.license_service import get_license_service

                if not get_license_service().is_tier_allowed(tier):
                    logger.warning(
                        f"Skipping package plugin '{plugin_id}': requires "
                        f"'{tier}' tier, current licence is "
                        f"'{get_license_service().get_tier()}'"
                    )
                    continue

                # V1/V2 signature gate. Signed → always load. Unsigned or
                # invalid → depends on tier and the operator opt-in:
                #   - community + allow_community_sideload=true → load with WARN
                #   - anything else (pro/enterprise, or toggle off) → skip
                from services.plugin_package_verifier import (
                    verify_package_signature,
                )

                sig_status = verify_package_signature(Path(package_dir))
                if sig_status != "verified":
                    tier_lower = str(tier or "community").lower()
                    if tier_lower == "community" and self._allow_community_sideload:
                        logger.warning(
                            f"Loading UNSIGNED community-tier package "
                            f"plugin '{plugin_id}' from {entry}/ "
                            f"(signature status: {sig_status}). "
                            "allow_community_sideload=true — this file "
                            "is trusted only because the operator opted in."
                        )
                    else:
                        logger.warning(
                            f"Skipping package plugin '{plugin_id}': "
                            f"signature status {sig_status}. "
                            f"Tier '{tier_lower}' requires a valid "
                            "signature. Set "
                            "plugin_settings.allow_community_sideload=true "
                            "in config/settings/plugins.yaml to allow "
                            "unsigned community-tier plugins (does NOT "
                            "cover pro/enterprise)."
                        )
                        continue

                entry_point = manifest.get("entry_point", "")
                entry_path = os.path.abspath(os.path.join(package_dir, entry_point))
                if not entry_path.startswith(os.path.abspath(package_dir) + os.sep):
                    logger.warning(
                        f"Skipping package plugin '{plugin_id}': entry_point "
                        f"escapes package directory"
                    )
                    continue
                if not os.path.isfile(entry_path):
                    logger.warning(
                        f"Skipping package plugin '{plugin_id}': entry_point "
                        f"'{entry_point}' not found"
                    )
                    continue

                spec = importlib.util.spec_from_file_location(module_name, entry_path)
                if spec is None or spec.loader is None:
                    logger.error(
                        f"Failed to create spec for package plugin: {plugin_id}"
                    )
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                class_name = manifest.get("class_name", "")
                plugin_class = getattr(module, class_name, None)
                if plugin_class is None or not inspect.isclass(plugin_class):
                    logger.warning(
                        f"Skipping package plugin '{plugin_id}': class "
                        f"'{class_name}' not found in entry point"
                    )
                    continue
                if not (
                    issubclass(plugin_class, BaseGPSPlugin)
                    or issubclass(plugin_class, BaseOutputPlugin)
                    or issubclass(plugin_class, BaseInboundPlugin)
                ):
                    logger.warning(
                        f"Skipping package plugin '{plugin_id}': class does not "
                        f"inherit a TrakBridge plugin base class"
                    )
                    continue

                logger.info(f"Loading package plugin: {plugin_id} from {entry}/")
                self.register_plugin(plugin_class)

            except Exception as e:
                logger.error(f"Failed to load package plugin '{entry}': {e}")

    def unregister_plugin(self, plugin_name: str) -> bool:
        """Remove a plugin from the registry. Returns True if it was present."""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            logger.info(f"Unregistered plugin: {plugin_name}")
            return True
        return False

    def is_builtin_plugin(self, plugin_name: str) -> bool:
        """True when the plugin was loaded from the built-in plugins package."""
        return plugin_name in self._builtin_plugin_names

    def load_external_plugins(self):
        """
        Load plugins from external directories (Docker volume mounts, etc.)
        """
        external_plugin_paths = [
            "/app/external_plugins",
            "/opt/trakbridge/plugins",
            os.path.expanduser("~/.trakbridge/plugins"),
            "./external_plugins",
        ]

        for path in external_plugin_paths:
            if os.path.exists(path) and os.path.isdir(path):
                logger.info(f"Loading external plugins from: {path}")
                self._load_external_plugins_directory(path)

    def _validate_module_name(self, module_name: str) -> bool:
        """
        Validate that a module name is in the allowed whitelist to prevent
        arbitrary code execution via dynamic imports.

        Enhanced with additional security checks to prevent path traversal
        and malicious module names.

        Args:
            module_name: The module name to validate

        Returns:
            bool: True if the module is allowed, False otherwise
        """
        import re

        # Basic input validation
        if not module_name or not isinstance(module_name, str):
            logger.error(f"Invalid module name type or empty: {type(module_name)}")
            return False

        # Security: Check for path traversal attempts
        if ".." in module_name or "/" in module_name or "\\" in module_name:
            logger.error(
                f"Path traversal attempt detected in module name: {module_name}"
            )
            return False

        # Security: Check for invalid characters that could be used for injection
        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$", module_name
        ):
            logger.error(f"Invalid characters in module name: {module_name}")
            return False

        # Security: Prevent loading of system/dangerous modules
        dangerous_prefixes = [
            "os",
            "sys",
            "subprocess",
            "importlib",
            "__builtins__",
            "eval",
            "exec",
        ]
        for prefix in dangerous_prefixes:
            if module_name.startswith(prefix + ".") or module_name == prefix:
                logger.error(
                    f"Attempted to load dangerous system module: {module_name}"
                )
                return False

        # Check if the module name is in our allowed modules set
        if module_name in self._allowed_modules:
            return True

        # Check if it's a submodule of an allowed module
        for allowed_module in self._allowed_modules:
            if module_name.startswith(allowed_module + "."):
                return True

        logger.warning(f"Attempted to load unauthorized plugin module: {module_name}")
        return False

    def register_plugin(
        self,
        plugin_class: Type[
            Union["BaseGPSPlugin", "BaseOutputPlugin", "BaseInboundPlugin"]
        ],
    ):
        """Register a plugin class (GPS input, output, or inbound plugin)"""

        plugin_name = None

        # Try to get plugin name from class method first
        if hasattr(plugin_class, "get_plugin_name"):
            try:
                plugin_name = plugin_class.get_plugin_name()
            except (AttributeError, TypeError) as e:
                logger.warning(f"Failed to get plugin name from class method: {e}")

        # Fall back to creating a temporary instance
        if not plugin_name:
            try:
                temp_instance = plugin_class({})
                plugin_name = temp_instance.plugin_name
            except (TypeError, ValueError) as e:
                logger.error(
                    f"Failed to create temporary instance for {plugin_class.__name__}: {e}"
                )
                return
            except Exception as e:
                logger.error(
                    f"Failed to get plugin name for {plugin_class.__name__}: {e}"
                )
                return

        self.plugins[plugin_name] = plugin_class
        logger.info(f"Registered plugin: {plugin_name}")

    @staticmethod
    def _validate_and_normalize_config(config: Union[Dict, str, None]) -> Dict:
        """
        Validate and normalize configuration input

        Args:
            config: Configuration input (can be dict, string, or None)

        Returns:
            Normalized dictionary configuration
        """
        if config is None:
            return {}

        if isinstance(config, str):
            # Handle string configuration - could be JSON, config name, or empty
            if not config or config.strip() == "":
                return {}

            # Try to parse as JSON with security validation
            try:
                return safe_json_loads(
                    config,
                    max_size=64 * 1024,  # 64KB limit for plugin configs
                    context="plugin_config_string",
                )
            except JSONValidationError as e:
                logger.warning(
                    f"JSON validation failed for config string: {e}. "
                    f"Details: {getattr(e, 'details', {})}"
                )
                return {}
            except (json.JSONDecodeError, ValueError) as e:
                # Fallback for other JSON errors
                logger.warning(
                    f"String config '{config[:100]}...' could not be parsed as JSON: {e}"
                )
                return {}

        if isinstance(config, dict):
            return config.copy()

        # For any other type, log warning and return empty dict
        logger.warning(f"Unexpected config type {type(config)}, using empty config")
        return {}

    def get_plugin_class(
        self, plugin_name: str
    ) -> Optional[
        Type[Union["BaseGPSPlugin", "BaseOutputPlugin", "BaseInboundPlugin"]]
    ]:
        """
        Get a plugin class by name without instantiation.

        Used by the inbound endpoint to instantiate plugins with stream-specific
        config and set the stream reference before validation.

        Args:
            plugin_name: Name of the registered plugin

        Returns:
            The plugin class, or None if not found
        """
        if plugin_name not in self.plugins:
            logger.error(f"Plugin class not found: {plugin_name}")
            return None
        return self.plugins[plugin_name]

    def get_plugin(
        self, plugin_name: str, config: Union[Dict, str, None] = None
    ) -> Optional[Union["BaseGPSPlugin", "BaseOutputPlugin"]]:
        """
        Create an instance of a plugin with the given configuration

        Args:
            plugin_name: Name of the plugin to instantiate
            config: Configuration (can be dict, string, or None)

        Returns:
            Plugin instance (GPS or output plugin) or None if creation fails
        """
        if plugin_name not in self.plugins:
            logger.error(f"Plugin not found: {plugin_name}")
            return None

        # Normalize configuration input
        normalized_config = self._validate_and_normalize_config(config)

        plugin_class = self.plugins[plugin_name]
        try:
            plugin_instance = plugin_class(normalized_config)
            if not plugin_instance.validate_config():
                logger.error(f"Plugin {plugin_name} configuration validation failed")
                return None
            return plugin_instance
        except Exception as e:
            logger.error(f"Failed to create plugin instance for '{plugin_name}': {e}")
            # Use secure logging to avoid exposing credentials in config
            from utils.security_helpers import safe_debug_log

            safe_debug_log(
                logger,
                f"Plugin creation failed for '{plugin_name}'",
                {
                    "config_type": str(type(config)),
                    "config_fields": (
                        len(config) if isinstance(config, dict) else "non-dict"
                    ),
                },
            )
            return None

    def list_plugins(self) -> List[str]:
        """List all registered plugin names"""
        return list(self.plugins.keys())

    def get_plugin_metadata(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific plugin"""
        if plugin_name not in self.plugins:
            return None

        plugin_class = self.plugins[plugin_name]
        try:
            # Create temporary instance to get metadata
            temp_instance = plugin_class({})
            return temp_instance.plugin_metadata
        except Exception as e:
            logger.error(f"Failed to get metadata for plugin {plugin_name}: {e}")
            return None

    def get_all_plugin_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Get metadata for all registered plugins"""
        metadata = {}
        for plugin_name in self.plugins:
            plugin_metadata = self.get_plugin_metadata(plugin_name)
            if plugin_metadata:
                metadata[plugin_name] = plugin_metadata
        return metadata

    def get_plugin_config_schema(
        self, plugin_name: str
    ) -> Optional[List[Dict[str, Any]]]:
        """Get configuration schema for a specific plugin"""
        if plugin_name not in self.plugins:
            return None

        plugin_class = self.plugins[plugin_name]
        try:
            temp_instance = plugin_class({})
            config_fields = temp_instance.get_config_fields()
            return [field.to_dict() for field in config_fields]
        except Exception as e:
            logger.error(f"Failed to get config schema for plugin {plugin_name}: {e}")
            return None

    def _get_config_hash(self, config: Dict[str, Any]) -> str:
        """Generate a hash of the configuration for caching purposes"""
        config_str = json.dumps(config, sort_keys=True)
        return hashlib.md5(config_str.encode()).hexdigest()

    @lru_cache(maxsize=128)
    def _cached_validate_plugin_config(
        self, plugin_name: str, config_hash: str, config_json: str
    ) -> Dict[str, Any]:
        """
        Cache expensive validation operations using @lru_cache.

        This method provides significant performance improvements for config saves
        by caching validation results based on plugin name and config hash.

        Args:
            plugin_name: Name of the plugin
            config_hash: MD5 hash of the configuration for cache key
            config_json: JSON representation of configuration

        Returns:
            Validation result dictionary
        """
        if plugin_name not in self.plugins:
            return {
                "valid": False,
                "errors": [f"Plugin '{plugin_name}' not found"],
                "warnings": [],
            }

        try:
            # Parse the JSON config
            config = json.loads(config_json) if config_json else {}
            plugin_class = self.plugins[plugin_name]
            plugin_instance = plugin_class(config)
            is_valid = plugin_instance.validate_config()

            return {
                "valid": is_valid,
                "errors": [] if is_valid else ["Configuration validation failed"],
                "warnings": [],
                "cached": True,  # Indicate this result was cached
            }
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "cached": True,
            }

    def validate_plugin_config(
        self, plugin_name: str, config: Union[Dict[str, Any], str, None]
    ) -> Dict[str, Any]:
        """
        Validate configuration for a specific plugin

        Args:
            plugin_name: Name of the plugin
            config: Configuration to validate (dict, string, or None)

        Returns:
            Dictionary with validation results:
            - valid: bool
            - errors: List[str]
            - warnings: List[str]
        """
        if plugin_name not in self.plugins:
            return {
                "valid": False,
                "errors": [f"Plugin '{plugin_name}' not found"],
                "warnings": [],
            }

        # Normalize configuration
        normalized_config = self._validate_and_normalize_config(config)

        # Use cached validation for performance improvement
        config_hash = self._get_config_hash(normalized_config)
        config_json = json.dumps(normalized_config, sort_keys=True)

        # Get cached result
        result = self._cached_validate_plugin_config(
            plugin_name, config_hash, config_json
        )

        # Add warnings for string conversion
        warnings = result.get("warnings", []).copy()
        if isinstance(config, str) and config.strip():
            warnings.append("String configuration was converted to dictionary")

        # Update warnings in result
        result = result.copy()
        result["warnings"] = warnings

        return result

    def clear_validation_cache(self):
        """Clear the validation cache to force fresh validation results"""
        self._cached_validate_plugin_config.cache_clear()
        logger.info("Plugin validation cache cleared")

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring purposes"""
        cache_info = self._cached_validate_plugin_config.cache_info()
        return {
            "hits": cache_info.hits,
            "misses": cache_info.misses,
            "current_size": cache_info.currsize,
            "max_size": cache_info.maxsize,
            "hit_ratio": (
                cache_info.hits / (cache_info.hits + cache_info.misses)
                if (cache_info.hits + cache_info.misses) > 0
                else 0.0
            ),
        }

    async def test_plugin_connection(
        self, plugin_name: str, config: Union[Dict[str, Any], str, None]
    ) -> Dict[str, Any]:
        """
        Test connection for a specific plugin configuration

        Args:
            plugin_name: Name of the plugin
            config: Configuration to test (dict, string, or None)

        Returns:
            Dictionary with connection test results from plugin's test_connection method
        """
        if plugin_name not in self.plugins:
            return {
                "success": False,
                "error": f"Plugin '{plugin_name}' not found",
                "message": "Plugin not found",
            }

        # Normalize configuration
        normalized_config = self._validate_and_normalize_config(config)

        plugin_class = self.plugins[plugin_name]
        try:
            plugin_instance = plugin_class(normalized_config)

            # Validate config first
            if not plugin_instance.validate_config():
                return {
                    "success": False,
                    "error": "Configuration validation failed",
                    "message": "Invalid configuration",
                }

            # Test connection
            return await plugin_instance.test_connection()

        except Exception as e:
            logger.error(f"Connection test failed for plugin {plugin_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Connection test error",
            }

    def get_plugins_by_category(self, category: str) -> List[str]:
        """Get plugins filtered by category"""
        matching_plugins = []
        for plugin_name in self.plugins:
            metadata = self.get_plugin_metadata(plugin_name)
            if metadata and metadata.get("category") == category:
                matching_plugins.append(plugin_name)
        return matching_plugins

    def get_inbound_plugins(self) -> List[str]:
        """Get all registered inbound plugins."""
        return self.get_plugins_by_category("inbound")

    def get_plugin_categories(self) -> List[str]:
        """Get all available plugin categories"""
        categories = set()
        for plugin_name in self.plugins:
            metadata = self.get_plugin_metadata(plugin_name)
            if metadata and metadata.get("category"):
                categories.add(metadata["category"])
        return sorted(list(categories))

    def load_plugins_from_directory(self, directory: str = "plugins"):
        """
        Automatically load plugins from a directory with security validation.
        Supports GPS input, output, and inbound plugins.
        """

        from plugins.base_plugin import (
            BaseGPSPlugin,
            BaseInboundPlugin,
            BaseOutputPlugin,
        )

        try:
            # Validate directory name for security (prevent path traversal)
            if ".." in directory or (
                "/" in directory and not directory.startswith("/app/external_plugins")
            ):
                logger.error(f"Invalid directory path detected: {directory}")
                return

            # Get absolute path of the plugins directory
            plugins_path = os.path.abspath(directory)

            if not os.path.exists(plugins_path):
                logger.warning(f"Plugins directory not found: {plugins_path}")
                return

            # Add plugins directory to Python path if not already there
            if plugins_path not in sys.path:
                sys.path.insert(0, plugins_path)

            # Handle external plugins directory differently
            if (
                directory.startswith("/app/external_plugins")
                or directory == "external_plugins"
            ):
                self._load_external_plugins_directory(plugins_path)
                return

            # Import the plugins package - validate first for security
            if not self._validate_module_name(directory):
                logger.error(
                    f"Unauthorized attempt to load plugin directory: {directory}"
                )
                return

            try:
                plugins_package = importlib.import_module(directory)
            except ImportError as e:
                logger.error(f"Failed to import plugin directory '{directory}': {e}")
                return
            except Exception as e:
                logger.error(
                    f"Unexpected error importing plugin directory '{directory}': {e}"
                )
                return

            # Iterate through all modules in the plugins package
            for importer, modname, ispkg in pkgutil.iter_modules(
                plugins_package.__path__, plugins_package.__name__ + "."
            ):
                # Skip the base_plugin module
                if modname.endswith(".base_plugin"):
                    continue

                try:
                    # Validate module name before importing for security
                    if not self._validate_module_name(modname):
                        logger.error(
                            f"Unauthorized attempt to load plugin module: {modname}"
                        )
                        continue

                    # Import the module with enhanced error handling
                    try:
                        module = importlib.import_module(modname)
                    except ImportError as e:
                        logger.error(f"Failed to import plugin module '{modname}': {e}")
                        continue
                    except Exception as e:
                        logger.error(
                            f"Unexpected error importing plugin module '{modname}': {e}"
                        )
                        continue

                    # Look for classes that inherit from BaseGPSPlugin, BaseOutputPlugin, or BaseInboundPlugin
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        # Check if it's a GPS plugin
                        if issubclass(obj, BaseGPSPlugin) and obj is not BaseGPSPlugin:
                            self.register_plugin(obj)
                        # Check if it's an output plugin
                        elif (
                            issubclass(obj, BaseOutputPlugin)
                            and obj is not BaseOutputPlugin
                        ):
                            self.register_plugin(obj)
                        # Check if it's an inbound plugin
                        elif (
                            issubclass(obj, BaseInboundPlugin)
                            and obj is not BaseInboundPlugin
                        ):
                            self.register_plugin(obj)

                except Exception as e:
                    logger.error(f"Failed to load plugin module {modname}: {e}")

            # Snapshot the names loaded from the built-in package so the admin
            # UI can mark them non-removable (externals load after this point)
            self._builtin_plugin_names.update(self.plugins.keys())

        except Exception as e:
            logger.error(f"Failed to load plugins from directory {directory}: {e}")

    def auto_discover_and_load_plugins(self, directory: str = "plugins"):
        """
        Alternative method that discovers Python files and loads them.
        Supports both GPS input plugins and output plugins.
        """

        from plugins.base_plugin import (
            BaseGPSPlugin,
            BaseInboundPlugin,
            BaseOutputPlugin,
        )

        try:
            plugins_path = os.path.abspath(directory)

            if not os.path.exists(plugins_path):
                logger.warning(f"Plugins directory not found: {plugins_path}")
                return

            # Get all Python files in the directory
            for filename in os.listdir(plugins_path):
                if (
                    filename.endswith(".py")
                    and not filename.startswith("__")
                    and filename != "base_plugin.py"
                ):
                    module_name = filename[:-3]  # Remove .py extension

                    try:
                        # Import the module
                        spec = importlib.util.spec_from_file_location(
                            module_name, os.path.join(plugins_path, filename)
                        )
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Look for plugin classes (GPS, output, and inbound plugins)
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if (
                                issubclass(obj, BaseGPSPlugin)
                                and obj is not BaseGPSPlugin
                            ):
                                self.register_plugin(obj)
                            elif (
                                issubclass(obj, BaseOutputPlugin)
                                and obj is not BaseOutputPlugin
                            ):
                                self.register_plugin(obj)
                            elif (
                                issubclass(obj, BaseInboundPlugin)
                                and obj is not BaseInboundPlugin
                            ):
                                self.register_plugin(obj)

                    except Exception as e:
                        logger.error(f"Failed to load plugin file {filename}: {e}")

        except Exception as e:
            logger.error(f"Failed to discover plugins in directory {directory}: {e}")

    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin (useful for development)"""
        from plugins.base_plugin import (
            BaseGPSPlugin,
            BaseInboundPlugin,
            BaseOutputPlugin,
        )

        if plugin_name not in self.plugins:
            logger.error(f"Cannot reload plugin '{plugin_name}': not found")
            return False

        try:
            plugin_class = self.plugins[plugin_name]
            module = inspect.getmodule(plugin_class)

            if module:
                importlib.reload(module)
                # Re-register the plugin (GPS, output, or inbound plugin)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    is_gps_plugin = (
                        issubclass(obj, BaseGPSPlugin) and obj is not BaseGPSPlugin
                    )
                    is_output_plugin = (
                        issubclass(obj, BaseOutputPlugin)
                        and obj is not BaseOutputPlugin
                    )
                    is_inbound_plugin = (
                        issubclass(obj, BaseInboundPlugin)
                        and obj is not BaseInboundPlugin
                    )

                    if is_gps_plugin or is_output_plugin or is_inbound_plugin:
                        # Check if this is the plugin we want to reload
                        try:
                            temp_instance = obj({})
                            if temp_instance.plugin_name == plugin_name:
                                self.plugins[plugin_name] = obj
                                logger.info(
                                    f"Successfully reloaded plugin: {plugin_name}"
                                )
                                return True
                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False

        return False

    def get_plugin_summary(self) -> Dict[str, Any]:
        """Get a summary of all loaded plugins"""
        summary = {
            "total_plugins": len(self.plugins),
            "plugins": {},
            "categories": self.get_plugin_categories(),
        }

        for plugin_name in self.plugins:
            metadata = self.get_plugin_metadata(plugin_name)
            if metadata:
                summary["plugins"][plugin_name] = {
                    "display_name": metadata.get("display_name", plugin_name),
                    "description": metadata.get("description", "No description"),
                    "category": metadata.get("category", "uncategorized"),
                    "config_fields_count": len(metadata.get("config_fields", [])),
                }

        return summary

    def safe_get_plugin(
        self,
        plugin_name: str,
        config: Union[Dict, str, None] = None,
        default_config: Optional[Dict] = None,
    ) -> Optional[Union["BaseGPSPlugin", "BaseOutputPlugin"]]:
        """
        Safely get a plugin with fallback configuration

        Args:
            plugin_name: Name of the plugin
            config: Primary configuration
            default_config: Fallback configuration if primary fails

        Returns:
            Plugin instance or None
        """
        # Try with primary config
        plugin = self.get_plugin(plugin_name, config)
        if plugin is not None:
            return plugin

        # Try with default config if provided
        if default_config is not None:
            logger.info(f"Falling back to default config for plugin {plugin_name}")
            return self.get_plugin(plugin_name, default_config)

        return None

    async def check_all_plugins_health(self):
        health_status = {}

        # Get existing stream configurations from the database
        from database import db
        from models.stream import Stream

        # Get all streams grouped by plugin type
        streams_by_plugin = {}
        try:
            streams = db.session.query(Stream).all()
            for stream in streams:
                plugin_type = stream.plugin_type
                if plugin_type not in streams_by_plugin:
                    streams_by_plugin[plugin_type] = []
                streams_by_plugin[plugin_type].append(stream)
        except Exception as e:
            logger.error(f"Could not fetch streams for health check: {e}")
            streams_by_plugin = {}

        for name, plugin_class in self.plugins.items():
            try:
                if name in streams_by_plugin and streams_by_plugin[name]:
                    # Test with actual stream configuration
                    stream = streams_by_plugin[name][0]  # Use first stream's config
                    config = (
                        stream.get_plugin_config()
                    )  # Use the method, not the attribute
                    plugin_instance = plugin_class(config)
                    health = await plugin_instance.health_check()

                    # Add stream count info to health details
                    stream_count = len(streams_by_plugin[name])
                    if isinstance(health, dict) and "details" in health:
                        if isinstance(health["details"], dict):
                            health["details"]["configured_streams"] = stream_count
                        else:
                            health["details"] = (
                                f"{health['details']} ({stream_count} stream(s) configured)"
                            )
                    else:
                        health["details"] = (
                            f"{health.get('details', 'Health check completed')} "
                            f"({stream_count} stream(s) configured)"
                        )

                else:
                    # No configured streams for this plugin
                    plugin_instance = plugin_class({})
                    health = {
                        "status": "unconfigured",
                        "details": "No streams configured for this plugin",
                    }

            except Exception as e:
                logger.error(
                    f"[PluginManager] Health check failed for plugin '{name}': {e}",
                    exc_info=True,
                )
                health = {"status": "unhealthy", "details": str(e)}
            health_status[name] = health
        return health_status


# Global plugin manager instance
plugin_manager = PluginManager()

# Auto-load plugins on import
plugin_manager.load_plugins_from_directory()
plugin_manager.load_external_plugins()


def get_plugin_manager():
    """Get the plugin manager instance - check Flask app context first, then fall back to global"""
    try:
        from flask import current_app, has_app_context

        if has_app_context() and hasattr(current_app, "plugin_manager"):
            return current_app.plugin_manager
    except (ImportError, RuntimeError):
        # Flask not available or no app context
        pass

    # Fallback to global instance for CLI/standalone use
    return plugin_manager
