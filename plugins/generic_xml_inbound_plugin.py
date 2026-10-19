# ABOUTME: Generic XML inbound plugin that receives XML payloads via HTTP POST
# ABOUTME: and maps configurable XPath fields to standard location dicts for CoT generation.

from datetime import datetime
from typing import Any, Dict, List, Optional

import defusedxml.ElementTree as ET

from plugins.base_plugin import BaseInboundPlugin, PluginConfigField
from services.logging_service import get_module_logger

logger = get_module_logger(__name__)


class GenericXMLInboundPlugin(BaseInboundPlugin):
    """
    Built-in plugin for receiving XML location data via HTTP POST.

    Uses defusedxml for safe parsing (XXE prevention) and configurable
    XPath expressions for field extraction.
    """

    PLUGIN_NAME = "generic_xml_inbound"

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
            "display_name": "XML Receiver",
            "description": (
                "Receive XML location data via HTTP POST with configurable "
                "XPath field mapping. Uses defusedxml for safe parsing."
            ),
            "icon": "fas fa-code",
            "category": "inbound",
            "accepted_content_types": ["application/xml", "text/xml"],
            "help_sections": [
                {
                    "title": "Overview",
                    "content": [
                        "Accepts XML payloads containing location data",
                        "Uses XPath expressions to locate device elements and fields",
                        "Safely parses XML using defusedxml (blocks XXE attacks)",
                        "Supports element text, attributes, and nested paths",
                    ],
                },
                {
                    "title": "XPath Mapping",
                    "content": [
                        "items_xpath: XPath to select device elements (e.g., //device)",
                        "lat_xpath / lon_xpath: relative XPath from each item to lat/lon",
                        "uid_xpath: relative XPath to unique device identifier",
                        "callsign_xpath: relative XPath to device display name",
                        "Use @attr for attribute values (e.g., @latitude)",
                        "Use child/grandchild for nested elements (e.g., position/lat)",
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
                    field_type="api_key",
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
                    name="items_xpath",
                    label="Items XPath",
                    field_type="text",
                    required=True,
                    default_value="//device",
                    placeholder="//device",
                    help_text=(
                        "XPath expression to select the repeating device elements "
                        "(e.g., //device, //tracker, /data/points/point)"
                    ),
                ),
                PluginConfigField(
                    name="lat_xpath",
                    label="Latitude XPath",
                    field_type="text",
                    required=True,
                    default_value="lat",
                    help_text="Relative XPath from each item to latitude (e.g., lat, position/lat, @latitude)",
                ),
                PluginConfigField(
                    name="lon_xpath",
                    label="Longitude XPath",
                    field_type="text",
                    required=True,
                    default_value="lon",
                    help_text="Relative XPath from each item to longitude (e.g., lon, position/lon, @longitude)",
                ),
                PluginConfigField(
                    name="uid_xpath",
                    label="UID XPath",
                    field_type="text",
                    required=True,
                    default_value="id",
                    help_text="Relative XPath from each item to unique identifier (e.g., id, @id, info/serial)",
                ),
                PluginConfigField(
                    name="callsign_xpath",
                    label="Callsign / Name XPath",
                    field_type="text",
                    required=True,
                    default_value="name",
                    help_text="Relative XPath from each item to display name (e.g., name, @name, info/label)",
                ),
                PluginConfigField(
                    name="timestamp_xpath",
                    label="Timestamp XPath",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="timestamp",
                    help_text="Relative XPath to ISO-8601 timestamp (optional)",
                ),
                PluginConfigField(
                    name="speed_xpath",
                    label="Speed XPath",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="speed",
                    help_text="Relative XPath to speed in m/s (optional)",
                ),
                PluginConfigField(
                    name="course_xpath",
                    label="Course / Heading XPath",
                    field_type="text",
                    required=False,
                    default_value="",
                    placeholder="course",
                    help_text="Relative XPath to heading in degrees (optional)",
                ),
                PluginConfigField(
                    name="preview_mode",
                    label="Preview Mode",
                    field_type="checkbox",
                    required=False,
                    default_value=True,
                    help_text=(
                        "Accept and transform payloads without forwarding "
                        "to TAK servers. The transformed result is returned "
                        "in the HTTP response so you can verify XPath "
                        "mapping. Turn off to deliver to TAK."
                    ),
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
        """Parse XML payload and map XPath fields to standard location dicts."""
        config = self.get_decrypted_config()

        # --- Parse XML safely ---
        try:
            root = ET.fromstring(raw_body)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML payload: {exc}") from exc
        except Exception as exc:
            # defusedxml raises specific exceptions for XXE, entity expansion, etc.
            raise ValueError(f"XML parsing rejected (possible XXE attack): {exc}") from exc

        # --- Find items via XPath ---
        items_xpath = config.get("items_xpath", "//device")
        # ElementTree.findall() requires ".//tag" not "//tag" on an element
        if items_xpath.startswith("//"):
            items_xpath = "." + items_xpath
        items = root.findall(items_xpath)

        if not items:
            raise ValueError(
                f"No locations found: items_xpath '{items_xpath}' matched 0 elements"
            )

        # --- Map each item ---
        locations: List[Dict[str, Any]] = []
        for idx, item in enumerate(items):
            loc = self._map_item(item, config, idx)
            locations.append(loc)

        return locations

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _map_item(
        self, item, config: Dict[str, Any], index: int
    ) -> Dict[str, Any]:
        """Map a single XML element to a standard location dict."""
        lat_xpath = config.get("lat_xpath", "lat")
        lon_xpath = config.get("lon_xpath", "lon")
        uid_xpath = config.get("uid_xpath", "id")
        callsign_xpath = config.get("callsign_xpath", "name")

        # --- Required fields ---
        raw_lat = self._resolve_xpath(item, lat_xpath)
        if raw_lat is None:
            raise ValueError(
                f"Required field '{lat_xpath}' (lat) not found in item {index}"
            )

        raw_lon = self._resolve_xpath(item, lon_xpath)
        if raw_lon is None:
            raise ValueError(
                f"Required field '{lon_xpath}' (lon) not found in item {index}"
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

        raw_uid = self._resolve_xpath(item, uid_xpath)
        uid = str(raw_uid) if raw_uid is not None else f"unknown-{index}"

        raw_name = self._resolve_xpath(item, callsign_xpath)
        name = str(raw_name) if raw_name is not None else f"Device-{index}"

        location: Dict[str, Any] = {
            "uid": uid,
            "name": name,
            "lat": lat,
            "lon": lon,
        }

        # --- Optional fields ---
        self._set_optional_field(
            location, "timestamp", item, config.get("timestamp_xpath", ""),
            converter=self._parse_timestamp,
        )
        self._set_optional_field(
            location, "speed", item, config.get("speed_xpath", ""),
            converter=float,
        )
        self._set_optional_field(
            location, "course", item, config.get("course_xpath", ""),
            converter=float,
        )

        return location

    @staticmethod
    def _resolve_xpath(element, xpath: str) -> Optional[str]:
        """
        Resolve a relative XPath against an element.

        Handles:
          - Attribute access: @attr_name
          - Child element text: child or child/grandchild
        """
        if not xpath:
            return None

        # Attribute access
        if xpath.startswith("@"):
            return element.get(xpath[1:])

        # Element text via find()
        child = element.find(xpath)
        if child is not None:
            return child.text

        return None

    def _set_optional_field(
        self,
        location: dict,
        key: str,
        item,
        xpath: str,
        converter=None,
    ) -> None:
        """Resolve an optional XPath field and add to location dict if present."""
        if not xpath:
            return
        raw = self._resolve_xpath(item, xpath)
        if raw is None:
            return
        if converter is not None:
            try:
                raw = converter(raw)
            except Exception:
                logger.debug(f"Could not convert optional field '{xpath}': {raw}")
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
