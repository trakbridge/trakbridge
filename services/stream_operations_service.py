"""
File: services/stream_operations_service.py

Description:
    Dedicated service for handling all stream lifecycle operations with proper
    separation of concerns from route handlers. This service provides a clean
    API layer between the web interface and the core stream management system,
    ensuring consistent error handling and business logic enforcement.

Key features:
    - Stream creation with automatic plugin configuration validation
    - Safe stream updates with stop/restart coordination to prevent data loss
    - Comprehensive stream deletion with proper cleanup and dependency handling
    - Bulk operations for starting/stopping multiple streams efficiently
    - Health check orchestration with detailed reporting and recovery actions
    - Auto-start functionality for newly created streams
    - Plugin configuration management with checkbox field handling
    - Database transaction management with rollback on errors
    - Stream enable/disable operations with database synchronization
    - Eager loading optimization for complex stream relationships
    - Comprehensive error handling with categorized exception types
    - Status validation and running state management
    - Plugin metadata integration for configuration validation
    - Thread-safe operations through StreamManager integration

Business Logic:
    - Enforces stream configuration validation before creation
    - Manages stream state transitions (inactive -> active -> running)
    - Handles plugin-specific configuration requirements
    - Provides consistent error responses for API consumption
    - Ensures proper cleanup during stream deletion operations
    - Coordinates database updates with stream manager operations

Author: Emfour Solutions
Created: 18-Jul-2025
"""

# Standard library imports
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional

# Local application imports
from models.stream import Stream
from services.exceptions import DatabaseError, StreamConfigurationError

# Worker coordination import removed for single worker deployment

logger = logging.getLogger(__name__)


class StreamOperationsService:
    """Service for handling stream lifecycle operations"""

    def __init__(self, stream_manager: Any, db: Any) -> None:
        self.stream_manager = stream_manager
        self.db = db
        # Use global worker coordination instance

    def _get_session(self):
        """Get the database session, handling both scoped session and db.session patterns"""
        return getattr(self.db, "session", self.db)

    def _is_concurrency_error(self, e: Exception) -> bool:
        """
        Universal concurrency error detection for all database types.

        Detects optimistic locking conflicts, deadlocks, and other concurrency issues
        that can occur when multiple processes try to update the same record.
        """
        from sqlalchemy.exc import IntegrityError, OperationalError

        error_str = str(e).lower()
        error_type = type(e).__name__

        # MariaDB/MySQL specific errors
        if "1020" in error_str or "record has changed since last read" in error_str:
            return True

        # PostgreSQL specific errors
        if isinstance(e, OperationalError):
            postgres_patterns = [
                "could not serialize access due to concurrent update",
                "deadlock detected",
                "tuple concurrently updated",
                "could not obtain lock on row",
            ]
            if any(pattern in error_str for pattern in postgres_patterns):
                return True

        # SQLite specific errors
        if isinstance(e, OperationalError):
            sqlite_patterns = [
                "database is locked",
                "database table is locked",
                "cannot start a transaction within a transaction",
                "disk i/o error",  # Can indicate lock contention
            ]
            if any(pattern in error_str for pattern in sqlite_patterns):
                return True

        # Generic IntegrityError that might indicate concurrency issues
        if isinstance(e, IntegrityError):
            # Some integrity errors are actually concurrency-related
            integrity_patterns = ["concurrent", "deadlock", "lock", "transaction"]
            if any(pattern in error_str for pattern in integrity_patterns):
                return True

        # Generic OperationalError during UPDATE operations (safe fallback)
        if isinstance(e, OperationalError):
            # If it's an OperationalError during what should be a simple UPDATE,
            # it's likely a concurrency issue worth retrying
            update_patterns = ["update", "set", "where"]
            if any(pattern in error_str for pattern in update_patterns):
                return True

        return False

    # Configuration change publishing removed for single worker deployment

    def _get_database_type(self) -> str:
        """Get the current database type for logging purposes"""
        try:
            engine = self._get_session().bind or self.db.engine
            return engine.dialect.name.lower()
        except Exception:
            return "unknown"

    def create_stream(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new stream with the provided data.
        Phase 2C: Enhanced to support both single-server and multi-server configurations.
        """
        try:
            # Simplified approach: Extract server IDs from tak_servers field and automatically determine mode
            server_ids_data = data.get("tak_servers", [])
            selected_server_ids = []

            # Handle both form data (list) and JSON data
            if isinstance(server_ids_data, list):
                selected_server_ids = [int(sid) for sid in server_ids_data if sid]
            elif server_ids_data:
                selected_server_ids = [int(server_ids_data)]

            # Fallback: Check for legacy field names for backward compatibility
            if not selected_server_ids:
                # Check legacy tak_server_id field
                if data.get("tak_server_id"):
                    selected_server_ids = [int(data["tak_server_id"])]
                # Check legacy tak_server_ids field
                elif data.get("tak_server_ids"):
                    legacy_ids = data["tak_server_ids"]
                    if isinstance(legacy_ids, list):
                        selected_server_ids = [int(sid) for sid in legacy_ids if sid]
                    else:
                        selected_server_ids = [int(legacy_ids)]

            if not selected_server_ids:
                return {
                    "success": False,
                    "error": "At least one TAK server must be selected",
                }

            # Verify all servers exist
            from models.tak_server import TakServer

            existing_servers = TakServer.query.filter(
                TakServer.id.in_(selected_server_ids)
            ).all()
            if len(existing_servers) != len(selected_server_ids):
                existing_ids = [s.id for s in existing_servers]
                missing_ids = [
                    sid for sid in selected_server_ids if sid not in existing_ids
                ]
                return {
                    "success": False,
                    "error": f"TAK servers not found: {missing_ids}",
                }

            # Automatic mode detection: 1 server = single mode, multiple = multi mode
            server_selection_mode = (
                "single" if len(selected_server_ids) == 1 else "multi"
            )
            tak_server_id = (
                selected_server_ids[0] if server_selection_mode == "single" else None
            )

            # Extract plugin config first to get cot_type_mode
            from plugins.plugin_manager import get_plugin_manager
            from services.stream_config_service import StreamConfigService

            plugin_manager = get_plugin_manager()
            config_service = StreamConfigService(plugin_manager)
            plugin_config = config_service.extract_plugin_config_from_request(data)

            # Get cot_type_mode from plugin config, fallback to form data, then default
            cot_type_mode = plugin_config.get("cot_type_mode") or data.get(
                "cot_type_mode", "stream"
            )

            # Determine stream mode from form data
            stream_mode = data.get("stream_mode", "poll")

            # Auto-generate API key for inbound HTTP streams if none provided
            if stream_mode == "inbound" and not plugin_config.get("api_key"):
                import secrets as _secrets
                plugin_config["api_key"] = _secrets.token_urlsafe(32)

            # Create stream with appropriate server configuration
            stream = Stream(
                name=data["name"],
                plugin_type=data["plugin_type"],
                poll_interval=int(data.get("poll_interval", 120)),
                cot_type=data.get("cot_type", "a-f-G-U-C"),
                cot_stale_time=int(data.get("cot_stale_time", 300)),
                tak_server_id=tak_server_id,  # Will be None for multi-server mode
                cot_type_mode=cot_type_mode,
                # Callsign mapping fields
                enable_callsign_mapping=bool(
                    data.get("enable_callsign_mapping", False)
                ),
                callsign_identifier_field=data.get("callsign_identifier_field"),
                callsign_error_handling=data.get(
                    "callsign_error_handling", "fallback"
                ),
                enable_per_callsign_cot_types=bool(
                    data.get("enable_per_callsign_cot_types", False)
                ),
                stream_mode=stream_mode,
            )

            # Set plugin configuration (already extracted above)
            stream.set_plugin_config(plugin_config)

            session = self._get_session()
            session.add(stream)
            session.flush()  # Flush to get stream.id for relationships

            # Phase 2C: Create multi-server relationships if in multi-server mode
            if server_selection_mode == "multi" and selected_server_ids:
                from models.tak_server import TakServer

                servers = TakServer.query.filter(
                    TakServer.id.in_(selected_server_ids)
                ).all()
                for server in servers:
                    stream.tak_servers.append(server)

                logger.info(
                    f"Created stream '{stream.name}' with {len(servers)} TAK servers: {[s.name for s in servers]}"
                )
            else:
                logger.info(
                    f"Created stream '{stream.name}' with single TAK server (ID: {tak_server_id})"
                )

            # Handle callsign mappings if enabled
            if stream.enable_callsign_mapping:
                self._create_callsign_mappings(stream, data)

            # Configuration change notification removed for single worker deployment

            session.commit()

            # Refresh TAK workers for the new stream configuration
            worker_refresh_success = self.stream_manager.refresh_stream_tak_workers(
                stream.id
            )
            if not worker_refresh_success:
                logger.warning(f"TAK worker refresh failed for new stream {stream.id}")

            # Auto-start if requested
            if data.get("auto_start"):
                try:
                    success = self.stream_manager.start_stream_sync(stream.id)
                    if success:
                        message = "Stream created and started successfully"
                    else:
                        message = "Stream created but failed to start automatically"
                except Exception as e:
                    logger.error(f"Error auto-starting stream: {e}")
                    message = "Stream created but failed to start automatically"
            else:
                message = "Stream created successfully"

            return {"success": True, "stream_id": stream.id, "message": message}

        except (ValueError, TypeError) as e:
            logger.error(f"Configuration error creating stream: {e}")
            return {"success": False, "error": f"Invalid configuration: {e}"}
        except StreamConfigurationError as e:
            logger.error(f"Stream configuration error: {e}")
            return {"success": False, "error": f"Configuration error: {e}"}
        except DatabaseError as e:
            logger.error(f"Database error creating stream: {e}")
            return {"success": False, "error": f"Database error: {e}"}
        except (OSError, RuntimeError) as e:
            logger.error(f"System error creating stream: {e}", exc_info=True)
            return {"success": False, "error": f"System error: {e}"}
        except Exception as e:
            logger.error(f"Unexpected error creating stream: {e}", exc_info=True)
            return {"success": False, "error": f"Unexpected error: {e}"}

    def start_stream_with_enable(self, stream_id: int) -> Dict[str, Any]:
        """Enable and start a stream"""
        try:
            # First, ensure the stream is enabled in the database
            stream = Stream.query.get_or_404(stream_id)

            # Enable the stream if it's not already enabled
            if not stream.is_active:
                stream.is_active = True
                self._get_session().commit()
                logger.info(f"Enabled stream {stream_id} ({stream.name})")

            # Now start the stream through StreamManager using the sync wrapper
            success = self.stream_manager.start_stream_sync(stream_id)

            if success:
                logger.info(f"Stream {stream_id} started successfully")
                return {"success": True, "message": "Stream started successfully"}
            else:
                logger.error(f"Failed to start stream {stream_id}")
                return {"success": False, "error": "Failed to start stream"}

        except Exception as e:
            logger.error(f"Error starting stream {stream_id}: {e}")
            return {"success": False, "error": str(e)}

    def stop_stream_with_disable(self, stream_id: int) -> Dict[str, Any]:
        """Stop and disable a stream"""
        try:
            # Update database status
            stream = Stream.query.get_or_404(stream_id)
            stream.is_active = False
            self._get_session().commit()
            logger.info(f"Disabled stream {stream_id} ({stream.name})")

            # Invalidate plugin cache before stopping (cleanup connections)
            from services.cot_service import get_cot_service
            cot_service = get_cot_service()
            if cot_service:
                cot_service.invalidate_plugin_cache_sync(stream_id)
                logger.debug(f"Invalidated plugin cache for stream {stream_id}")

            # Stop the stream through StreamManager using the sync wrapper
            success = self.stream_manager.stop_stream_sync(stream_id)

            if success:
                logger.info(f"Stream {stream_id} stopped successfully")
                return {"success": True, "message": "Stream stopped successfully"}
            else:
                logger.error(f"Failed to stop stream {stream_id}")
                return {"success": False, "error": "Failed to stop stream"}

        except Exception as e:
            logger.error(f"Error stopping stream {stream_id}: {e}")
            return {"success": False, "error": str(e)}

    def restart_stream(self, stream_id: int) -> Dict[str, Any]:
        """Restart a stream"""
        try:
            # Invalidate plugin cache before restart (cleanup old connections)
            from services.cot_service import get_cot_service
            cot_service = get_cot_service()
            if cot_service:
                cot_service.invalidate_plugin_cache_sync(stream_id)
                logger.debug(f"Invalidated plugin cache for stream {stream_id} before restart")

            # Use the stream manager's sync wrapper for restart
            success = self.stream_manager.restart_stream_sync(stream_id)

            if success:
                logger.info(f"Stream {stream_id} restarted successfully")
                return {"success": True, "message": "Stream restarted successfully"}
            else:
                logger.error(f"Failed to restart stream {stream_id}")
                return {"success": False, "error": "Failed to restart stream"}

        except Exception as e:
            logger.error(f"Error restarting stream {stream_id}: {e}")
            return {"success": False, "error": str(e)}

    def delete_stream(self, stream_id: int) -> Dict[str, Any]:
        """Delete a stream"""
        try:
            stream = Stream.query.get_or_404(stream_id)

            # Stop the stream if it's running
            if stream.is_active:
                try:
                    # Invalidate cache before stopping (cleanup connections)
                    from services.cot_service import get_cot_service
                    cot_service = get_cot_service()
                    if cot_service:
                        cot_service.invalidate_plugin_cache_sync(stream_id)
                        logger.debug(f"Invalidated plugin cache for stream {stream_id} before deletion")

                    self.stream_manager.stop_stream_sync(stream_id)
                except Exception as e:
                    logger.warning(f"Error stopping stream before deletion: {e}")

            # Delete from database
            session = self._get_session()
            session.delete(stream)
            session.commit()

            logger.info(f"Stream {stream_id} deleted successfully")
            return {"success": True, "message": "Stream deleted successfully"}

        except Exception as e:
            logger.error(f"Error deleting stream {stream_id}: {e}")
            self._get_session().rollback()
            return {"success": False, "error": str(e)}

    def update_stream_safely(
        self, stream_id: int, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update stream with universal optimistic locking for all database types"""
        import time
        from sqlalchemy.orm import joinedload

        max_retries = 3
        retry_delay = 0.1  # 100ms initial delay
        db_type = self._get_database_type()

        for attempt in range(max_retries):
            try:
                # Get stream with eager loading - fresh copy for each attempt
                stream = (
                    Stream.query.options(joinedload(Stream.tak_server))
                    .filter_by(id=stream_id)
                    .first_or_404()
                )

                # Check if the stream is currently running
                stream_status = self._safe_get_stream_status(stream_id)
                was_running = stream_status.get("running", False)

                # Stop the stream if it's running (we'll restart it after update)
                if was_running:
                    self.stream_manager.stop_stream_sync(stream_id)
                    # Give the stream worker a moment to finish any pending operations
                    time.sleep(0.1)

                # Re-fetch the stream after stopping to get the latest state
                # This prevents race conditions with the stream worker's final updates
                if was_running:
                    self._get_session().refresh(stream)

                # Update basic stream properties
                stream.name = data["name"]
                stream.plugin_type = data["plugin_type"]
                stream.poll_interval = int(data.get("poll_interval", 120))
                stream.cot_type = data.get("cot_type", "a-f-G-U-C")
                stream.cot_stale_time = int(data.get("cot_stale_time", 300))
                # Note: cot_type_mode will be updated from plugin config later in this method

                # Simplified approach: Handle server assignment with automatic mode detection
                server_ids_data = data.get("tak_servers", [])
                selected_server_ids = []

                # Handle both form data (list) and JSON data
                if isinstance(server_ids_data, list):
                    selected_server_ids = [int(sid) for sid in server_ids_data if sid]
                elif server_ids_data:
                    selected_server_ids = [int(server_ids_data)]

                # Fallback: Check for legacy field names for backward compatibility
                if not selected_server_ids:
                    # Check legacy tak_server_id field
                    if data.get("tak_server_id"):
                        selected_server_ids = [int(data["tak_server_id"])]
                    # Check legacy tak_server_ids field
                    elif data.get("tak_server_ids"):
                        legacy_ids = data["tak_server_ids"]
                        if isinstance(legacy_ids, list):
                            selected_server_ids = [
                                int(sid) for sid in legacy_ids if sid
                            ]
                        else:
                            selected_server_ids = [int(legacy_ids)]

                if not selected_server_ids:
                    return {
                        "success": False,
                        "error": "At least one TAK server must be selected",
                    }

                # Verify all servers exist
                from models.tak_server import TakServer

                existing_servers = TakServer.query.filter(
                    TakServer.id.in_(selected_server_ids)
                ).all()
                if len(existing_servers) != len(selected_server_ids):
                    existing_ids = [s.id for s in existing_servers]
                    missing_ids = [
                        sid for sid in selected_server_ids if sid not in existing_ids
                    ]
                    return {
                        "success": False,
                        "error": f"TAK servers not found: {missing_ids}",
                    }

                # Automatic mode detection: 1 server = single mode, multiple = multi mode
                server_selection_mode = (
                    "single" if len(selected_server_ids) == 1 else "multi"
                )

                if server_selection_mode == "single":
                    # Clear multi-server relationships and set single server
                    servers_to_remove = list(stream.tak_servers)
                    for existing_server in servers_to_remove:
                        stream.tak_servers.remove(existing_server)
                    stream.tak_server_id = selected_server_ids[0]
                    logger.info(
                        f"Updated stream '{stream.name}' to single TAK server: {existing_servers[0].name}"
                    )
                else:
                    # Clear single server relationship and set multi-server relationships
                    stream.tak_server_id = None
                    servers_to_remove = list(stream.tak_servers)
                    for existing_server in servers_to_remove:
                        stream.tak_servers.remove(existing_server)

                    for server in existing_servers:
                        stream.tak_servers.append(server)

                    logger.info(
                        f"Updated stream '{stream.name}' to multi-server mode with {len(existing_servers)} servers: {[s.name for s in existing_servers]}"
                    )

                # Update callsign mapping fields
                stream.enable_callsign_mapping = bool(
                    data.get("enable_callsign_mapping", False)
                )
                stream.callsign_identifier_field = data.get("callsign_identifier_field")
                stream.callsign_error_handling = data.get(
                    "callsign_error_handling", "fallback"
                )
                stream.enable_per_callsign_cot_types = bool(
                    data.get("enable_per_callsign_cot_types", False)
                )

                # Update inbound stream fields
                stream_mode = data.get("stream_mode", stream.stream_mode or "poll")
                stream.stream_mode = stream_mode

                # Update plugin configuration with password preservation
                from plugins.plugin_manager import get_plugin_manager
                from services.stream_config_service import StreamConfigService

                plugin_manager = get_plugin_manager()
                config_service = StreamConfigService(plugin_manager)
                plugin_type = data.get("plugin_type")

                # Extract plugin config from request data
                plugin_config = config_service.extract_plugin_config_from_request(data)
                logger.debug(
                    f"Extracted plugin config for {plugin_type}: {plugin_config}"
                )

                # Merge with existing config to preserve encrypted password fields
                merged_config = config_service.merge_plugin_config_with_existing(
                    plugin_config, plugin_type, stream_id
                )
                logger.debug(f"Merged plugin config for {plugin_type}: {merged_config}")

                # Copy certain plugin config values to stream-level fields
                # This restores functionality that was removed in commit 48edfe59
                # Note: cot_type_mode is now handled during stream creation
                if "cot_type_mode" in merged_config:
                    stream.cot_type_mode = merged_config["cot_type_mode"]
                    logger.debug(
                        f"Updated stream cot_type_mode to: {merged_config['cot_type_mode']}"
                    )

                # Handle missing checkbox fields for all plugins
                if plugin_type:
                    metadata = plugin_manager.get_plugin_metadata(plugin_type)
                    if metadata:
                        for field in metadata.get("config_fields", []):
                            # Handle both dict and object (e.g., PluginConfigField)
                            if (
                                isinstance(field, dict)
                                and field.get("field_type") == "checkbox"
                            ) or (
                                hasattr(field, "field_type")
                                and getattr(field, "field_type") == "checkbox"
                            ):
                                field_name = (
                                    field["name"]
                                    if isinstance(field, dict)
                                    else getattr(field, "name")
                                )
                                if field_name not in merged_config:
                                    merged_config[field_name] = False

                stream.set_plugin_config(merged_config)

                # Save-time plugin config validation. Plugin validate_config()
                # normally returns bool, but our operator-facing checks (e.g.
                # T1.3 auth_mode/ip_allowlist) raise ValueError with a
                # user-readable message so the UI can surface the reason.
                try:
                    from plugins.plugin_manager import get_plugin_manager
                    pm = get_plugin_manager()
                    plugin_class = pm.get_plugin_class(stream.plugin_type)
                    if plugin_class is not None:
                        probe = plugin_class(merged_config)
                        probe.stream = stream
                        probe.validate_config()
                except ValueError as ve:
                    self._get_session().rollback()
                    return {"success": False, "error": str(ve)}

                # Update callsign mappings if enabled
                if stream.enable_callsign_mapping:
                    self._update_callsign_mappings(stream, data)

                # Configuration change notification removed for single worker deployment

                # Attempt to commit the transaction
                self._get_session().commit()

                logger.debug(
                    f"Stream {stream_id} updated successfully on {db_type} (attempt {attempt + 1})"
                )

                # Invalidate plugin cache so it reloads with new config
                from services.cot_service import get_cot_service
                cot_service = get_cot_service()
                if cot_service:
                    cot_service.invalidate_plugin_cache_sync(stream_id)
                    logger.debug(f"Invalidated plugin cache for stream {stream_id}")

                # Refresh TAK workers to match new configuration
                worker_refresh_success = self.stream_manager.refresh_stream_tak_workers(
                    stream_id
                )
                if not worker_refresh_success:
                    logger.warning(
                        f"TAK worker refresh failed for stream {stream_id}, but update succeeded"
                    )

                # Restart the stream if it was running before
                if was_running:
                    self.stream_manager.restart_stream_sync(stream_id)

                return {
                    "success": True,
                    "stream_id": stream.id,
                    "message": "Stream updated successfully",
                }

            except Exception as e:
                # Check if this is a concurrency error using universal detection
                if self._is_concurrency_error(e):
                    self._get_session().rollback()
                    if attempt < max_retries - 1:
                        retry_delay_with_jitter = retry_delay * (2**attempt) + (
                            attempt * 0.05
                        )
                        logger.warning(
                            f"Concurrency conflict on {db_type} updating stream {stream_id} "
                            f"(attempt {attempt + 1}/{max_retries}), retrying in {retry_delay_with_jitter:.2f}s"
                        )
                        time.sleep(retry_delay_with_jitter)
                        continue
                    else:
                        logger.error(
                            f"Failed to update stream {stream_id} on {db_type} after {max_retries} attempts "
                            f"due to concurrency conflicts"
                        )
                        return {
                            "success": False,
                            "error": "Stream update failed due to concurrent modifications. Please try again.",
                            "error_type": "concurrency_conflict",
                        }
                else:
                    # Non-concurrency error, don't retry
                    self._get_session().rollback()
                    logger.error(
                        f"Non-retryable error updating stream {stream_id} on {db_type}: {e}"
                    )
                    return {"success": False, "error": str(e)}

        # This should never be reached, but just in case
        return {"success": False, "error": "Unexpected error in update retry logic"}

    def run_health_check(self) -> Dict[str, Any]:
        """Trigger a health check on all streams"""
        try:
            # Run health check in the background event loop
            future = asyncio.run_coroutine_threadsafe(
                self.stream_manager.health_check(), self.stream_manager.loop
            )
            future.result(timeout=30)

            return {"success": True, "message": "Health check completed"}

        except Exception as e:
            logger.error(f"Error during health check: {e}")
            return {"success": False, "error": str(e)}

    def bulk_start_streams(self) -> Dict[str, Any]:
        """Start all active streams"""
        try:
            active_streams = Stream.query.filter_by(is_active=True).all()
            started_count = 0
            failed_count = 0

            for stream in active_streams:
                try:
                    success = self.stream_manager.start_stream_sync(stream.id)
                    if success:
                        started_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Error starting stream {stream.id}: {e}")
                    failed_count += 1

            return {
                "success": True,
                "message": f"Started {started_count} streams, {failed_count} failed",
                "started": started_count,
                "failed": failed_count,
            }

        except Exception as e:
            logger.error(f"Error starting all streams: {e}")
            return {"success": False, "error": str(e)}

    def bulk_stop_streams(self) -> Dict[str, Any]:
        """Stop all running streams"""
        try:
            # Get running status with error handling
            try:
                running_status = self.stream_manager.get_all_stream_status()
            except Exception as e:
                logger.error(f"Error getting stream manager status: {e}")
                running_status = {}

            # Find running streams with improved error handling
            running_streams = []
            if isinstance(running_status, dict):
                for stream_id, status in running_status.items():
                    if isinstance(status, dict) and status.get("running", False):
                        running_streams.append(stream_id)
                    # Skip non-dict status values as they're likely not running

            stopped_count = 0
            failed_count = 0

            for stream_id in running_streams:
                try:
                    success = self.stream_manager.stop_stream_sync(stream_id)
                    if success:
                        stopped_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Error stopping stream {stream_id}: {e}")
                    failed_count += 1

            return {
                "success": True,
                "message": f"Stopped {stopped_count} streams, {failed_count} failed",
                "stopped": stopped_count,
                "failed": failed_count,
            }

        except Exception as e:
            logger.error(f"Error stopping all streams: {e}")
            return {"success": False, "error": str(e)}

    def _safe_get_stream_status(self, stream_id: int) -> Optional[Dict[str, Any]]:
        """Safely get stream status, ensuring it returns a dict"""
        try:
            status = self.stream_manager.get_stream_status(stream_id)
            # Ensure status is always a dictionary
            if not isinstance(status, dict):
                logger.warning(
                    f"Stream status for {stream_id} is not a dict: {type(status)} - {status}"
                )
                # If it's a datetime object, it might be last_poll time - convert appropriately
                if isinstance(status, datetime):
                    return {
                        "running": False,
                        "last_poll": status.isoformat(),
                        "error": None,
                    }
                else:
                    return {"running": False, "error": "Invalid status format"}
            return status
        except Exception as e:
            logger.error(f"Error getting status for stream {stream_id}: {e}")
            return {"running": False, "error": str(e)}

    def _create_callsign_mappings(self, stream: Any, data: Dict[str, Any]) -> None:
        """Create callsign mappings from form data"""
        from models.callsign_mapping import CallsignMapping

        # Extract callsign mapping data from form
        mapping_index = 0
        while any(
            key.startswith(f"callsign_mapping_{mapping_index}_") for key in data.keys()
        ):
            identifier_key = f"callsign_mapping_{mapping_index}_identifier"
            callsign_key = f"callsign_mapping_{mapping_index}_callsign"
            cot_type_key = f"callsign_mapping_{mapping_index}_cot_type"
            enabled_key = f"callsign_mapping_{mapping_index}_enabled"
            cot_type_override_key = f"callsign_mapping_{mapping_index}_cot_type_override"
            team_role_key = f"callsign_mapping_{mapping_index}_team_role"
            team_color_key = f"callsign_mapping_{mapping_index}_team_color"

            identifier_value = data.get(identifier_key)
            custom_callsign = data.get(callsign_key)
            cot_type = data.get(cot_type_key) or None  # Empty string becomes None
            cot_type_override = data.get(cot_type_override_key) or None  # Empty string becomes None
            team_role = data.get(team_role_key) or None  # Empty string becomes None
            team_color = data.get(team_color_key) or None  # Empty string becomes None

            # Handle enabled field - checkbox data comes as 'on' or not present
            enabled_value = data.get(enabled_key)
            enabled = True  # Default to enabled

            if isinstance(enabled_value, str):
                # Form checkbox data: 'on' means checked/enabled, missing means unchecked/disabled
                enabled = enabled_value.lower() in ("on", "true", "1")
            elif isinstance(enabled_value, bool):
                # Direct boolean value (from JSON)
                enabled = enabled_value
            elif enabled_value is None:
                # Missing checkbox means disabled (unchecked)
                enabled = False

            # Create mapping if identifier is provided (even for disabled trackers)
            # This ensures disabled trackers are saved with enabled=False
            if identifier_value:
                mapping = CallsignMapping(
                    stream_id=stream.id,
                    identifier_value=identifier_value,
                    custom_callsign=custom_callsign
                    or "",  # Form data should include callsign
                    cot_type=cot_type,
                    enabled=enabled,
                    cot_type_override=cot_type_override,
                    team_role=team_role,
                    team_color=team_color,
                )
                self._get_session().add(mapping)

            mapping_index += 1

    def _update_callsign_mappings(self, stream: Any, data: Dict[str, Any]) -> None:
        """Update callsign mappings from form data"""
        from models.callsign_mapping import CallsignMapping

        # Clear existing mappings for this stream
        CallsignMapping.query.filter_by(stream_id=stream.id).delete()

        # Create new mappings from form data (reuse the create logic)
        self._create_callsign_mappings(stream, data)
