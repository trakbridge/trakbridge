# ABOUTME: Generic JSON inbound plugin that receives JSON payloads via HTTP POST
# ABOUTME: and maps configurable fields to standard location dicts for CoT generation.

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from plugins.base_plugin import BaseInboundPlugin, PluginConfigField
from services.logging_service import get_module_logger

logger = get_module_logger(__name__)

# Sentinel for "field not found" so we can distinguish from None values
_MISSING = object()


def resolve_path(data: dict, path: str) -> Any:
    """
    Resolve a dot-notation path against a nested dict.

    Examples:
        resolve_path({"a": {"b": 1}}, "a.b") → 1
        resolve_path({"x": 5}, "x") → 5
        resolve_path({"x": 5}, "y") → _MISSING

    Returns _MISSING sentinel if any segment is missing.
    """
    current = data
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


class GenericInboundPlugin(BaseInboundPlugin):
    """
    Built-in plugin for receiving JSON location data via HTTP POST.

    Supports configurable dot-notation field mapping so users can adapt
    to any JSON schema without writing custom plugin code.
    """

    PLUGIN_NAME = "generic_json_inbound"

    @property
    def plugin_name(self) -> str:
        return self.PLUGIN_NAME

    @classmethod
    def get_plugin_name(cls) -> str:
        """Class method to get plugin name without instantiation."""
        return cls.PLUGIN_NAME

    @property
    def plugin_metadata(self) -> Dict[str, Any]:
        return {
            "display_name": "JSON Receiver",
            "description": (
                "Receive JSON location data via HTTP POST with configurable "
                "field mapping. Supports flat and nested JSON structures."
            ),
            "icon": "fas fa-arrow-circle-down",
            "category": "inbound",
            "accepted_content_types": ["application/json"],
            "help_sections": [
                {
                    "title": "Overview",
                    "content": [
                        "Accepts JSON payloads containing location data",
                        "Supports single objects and arrays of objects",
                        "Use dot-notation for nested fields (e.g., position.latitude)",
                        "Configure items_path to extract arrays from nested structures",
                    ],
                },
                {
                    "title": "Field Mapping",
                    "content": [
                        "lat_field / lon_field: paths to latitude and longitude (required)",
                        "uid_field: path to a unique device identifier",
                        "callsign_field: path to the device display name",
                        "timestamp_field, speed_field, course_field: optional telemetry",
                        "All fields support dot-notation (e.g., data.gps.lat)",
                    ],
                },
            ],
            "config_fields": [
                PluginConfigField(
                    name="auth_mode",
                    label="Authentication Mode",
                    field_type="select",
                    required=False,
                    default_value="api_key",
                    options=[
                        {"value": "api_key", "label": "API Key (Bearer Token)"},
                        {"value": "none", "label": "No Authentication"},
                    ],
                    help_text=(
                        "API Key mode requires a Bearer token in the Authorization header. "
                        "'No Authentication' must be explicitly chosen for testing only."
                    ),
                ),
                PluginConfigField(
                    name="api_key",
                    label="API Key",
                    field_type="password",
                    required=False,
                    sensitive=True,
                    help_text="Secret key sent as Bearer token in the Authorization header",
                ),
                PluginConfigField(
                    name="ip_allowlist",
                    label="Source IP Allowlist",
                    field_type="textarea",
                    required=False,
                    placeholder="10.0.0.0/8\n192.168.1.42\n0.0.0.0/0",
                    help_text=(
                        "Comma- or newline-separated IPs and/or CIDR "
                        "blocks. Required when Authentication Mode is "
                        "'No Authentication'. Use 0.0.0.0/0 to "
                        "explicitly accept any IP (documents an "
                        "intentional choice)."
                    ),
                ),
                PluginConfigField(
                    name="items_path",
                    label="Items Path",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="data.devices",
                    help_text=(
                        "Dot-notation path to the array of items within the JSON payload. "
                        "Leave empty if the root is the array or a single object."
                    ),
                ),
                PluginConfigField(
                    name="lat_field",
                    label="Latitude Field",
                    field_type="text",
                    required=True,
                    default_value="lat",
                    help_text="Dot-notation path to latitude (e.g., position.latitude)",
                ),
                PluginConfigField(
                    name="lon_field",
                    label="Longitude Field",
                    field_type="text",
                    required=True,
                    default_value="lon",
                    help_text="Dot-notation path to longitude (e.g., position.longitude)",
                ),
                PluginConfigField(
                    name="uid_field",
                    label="UID Field",
                    field_type="text",
                    required=True,
                    default_value="id",
                    help_text="Dot-notation path to unique device identifier",
                ),
                PluginConfigField(
                    name="callsign_field",
                    label="Callsign / Name Field",
                    field_type="text",
                    required=True,
                    default_value="name",
                    help_text="Dot-notation path to device display name / callsign",
                ),
                PluginConfigField(
                    name="timestamp_field",
                    label="Timestamp Field",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="timestamp",
                    help_text="Dot-notation path to ISO-8601 timestamp (optional)",
                ),
                PluginConfigField(
                    name="speed_field",
                    label="Speed Field",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="speed",
                    help_text="Dot-notation path to speed in m/s (optional)",
                ),
                PluginConfigField(
                    name="course_field",
                    label="Course / Heading Field",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="course",
                    help_text="Dot-notation path to heading in degrees (optional)",
                ),
            ],
        }

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_config(self) -> bool:
        if not super().validate_config():
            return False

        import ipaddress

        config = self.get_decrypted_config()
        auth_mode = str(config.get("auth_mode", "api_key")).lower()
        allowlist = str(config.get("ip_allowlist") or "").strip()

        if auth_mode == "none" and not allowlist:
            raise ValueError(
                "Authentication Mode 'No Authentication' requires a "
                "non-empty Source IP Allowlist. Enter 0.0.0.0/0 to "
                "accept any IP, or switch to API Key authentication."
            )

        if allowlist:
            for entry in allowlist.replace(",", "\n").splitlines():
                entry = entry.strip()
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise ValueError(
                        f"Source IP Allowlist entry '{entry}' is not "
                        "a valid IP address or CIDR block."
                    )

        return True

    # ------------------------------------------------------------------
    # Payload transformation
    # ------------------------------------------------------------------

    def transform_payload(
        self,
        raw_body: bytes,
        content_type: str,
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Parse JSON payload and map fields to standard location dicts."""
        config = self.get_decrypted_config()

        # --- Parse JSON ---
        try:
            data = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc

        if data is None:
            raise ValueError("Invalid JSON payload: received null")

        # --- Resolve items_path to get the list of items ---
        items = self._extract_items(data, config.get("items_path", ""))

        if not items:
            raise ValueError("No locations found in payload")

        # --- Map each item to a location dict ---
        locations: List[Dict[str, Any]] = []
        for idx, item in enumerate(items):
            loc = self._map_item(item, config, idx)
            locations.append(loc)

        return locations

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_items(self, data: Any, items_path: str) -> List[dict]:
        """
        Extract the list of items from the parsed JSON.

        If items_path is empty, treat the root as the items source.
        """
        if items_path:
            resolved = resolve_path(data, items_path)
            if resolved is _MISSING:
                raise ValueError(
                    f"items_path '{items_path}' not found in payload"
                )
            data = resolved

        # Normalise to list
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data

        raise ValueError(
            f"Expected JSON object or array, got {type(data).__name__}"
        )

    def _map_item(
        self, item: dict, config: Dict[str, Any], index: int
    ) -> Dict[str, Any]:
        """Map a single JSON item to a standard location dict."""
        lat_field = config.get("lat_field", "lat")
        lon_field = config.get("lon_field", "lon")
        uid_field = config.get("uid_field", "id")
        callsign_field = config.get("callsign_field", "name")

        # --- Required fields ---
        raw_lat = resolve_path(item, lat_field)
        if raw_lat is _MISSING:
            raise ValueError(
                f"Required field '{lat_field}' (lat) not found in item {index}"
            )

        raw_lon = resolve_path(item, lon_field)
        if raw_lon is _MISSING:
            raise ValueError(
                f"Required field '{lon_field}' (lon) not found in item {index}"
            )

        try:
            lat = float(raw_lat)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Cannot convert lat value '{raw_lat}' to float in item {index}"
            ) from exc

        try:
            lon = float(raw_lon)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Cannot convert lon value '{raw_lon}' to float in item {index}"
            ) from exc

        raw_uid = resolve_path(item, uid_field)
        uid = str(raw_uid) if raw_uid is not _MISSING else f"unknown-{index}"

        raw_name = resolve_path(item, callsign_field)
        name = str(raw_name) if raw_name is not _MISSING else f"Device-{index}"

        location: Dict[str, Any] = {
            "uid": uid,
            "name": name,
            "lat": lat,
            "lon": lon,
        }

        # --- Optional fields ---
        self._set_optional_field(
            location, "timestamp", item, config.get("timestamp_field", ""),
            converter=self._parse_timestamp,
        )
        self._set_optional_field(
            location, "speed", item, config.get("speed_field", ""),
            converter=float,
        )
        self._set_optional_field(
            location, "course", item, config.get("course_field", ""),
            converter=float,
        )

        return location

    @staticmethod
    def _set_optional_field(
        location: dict,
        key: str,
        item: dict,
        field_path: str,
        converter=None,
    ) -> None:
        """Resolve an optional field and add it to the location dict if present."""
        if not field_path:
            return
        raw = resolve_path(item, field_path)
        if raw is _MISSING:
            return
        if converter is not None:
            try:
                raw = converter(raw)
            except Exception:
                logger.debug(f"Could not convert optional field '{field_path}': {raw}")
                return
        location[key] = raw

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Parse an ISO-8601 timestamp string to a datetime object."""
        if isinstance(value, datetime):
            return value
        ts_str = str(value)
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
