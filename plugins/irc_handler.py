# ABOUTME: IRCHandler plugin for receiving CoT messages from TAK and posting to IRC
# ABOUTME: Implements BaseOutputPlugin to handle chat messages and route them to IRC channels

from plugins.base_plugin import (
    BaseOutputPlugin,
    PluginConfigField,
    PluginCustomComponent,
)
from defusedxml import ElementTree as DefusedET
import asyncio
import time
from typing import Any, Dict, List, Optional
import re
import mgrs


# Lazy import to avoid circular dependency
_logger_instance = None


def get_logger():
    """Get the module logger, initializing lazily to avoid circular imports"""
    global _logger_instance
    if _logger_instance is None:
        from services.logging_service import get_module_logger

        _logger_instance = get_module_logger(__name__)
    return _logger_instance


# For backwards compatibility - provide logger as module attribute
class _LoggerProxy:
    """Proxy that forwards all attribute access to the lazy logger"""

    def __getattr__(self, name):
        return getattr(get_logger(), name)


logger = _LoggerProxy()


class IRCHandler(BaseOutputPlugin):
    """Handle CoT messages and send to IRC"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected: bool = False
        self._connection_lock = asyncio.Lock()
        self._ping_task: Optional[asyncio.Task] = None
        self._reader_task: Optional[asyncio.Task] = None
        # Deduplication: track recently seen messages to avoid duplicates from TAK server
        self._seen_messages: Dict[str, float] = {}
        self._dedup_ttl_seconds: float = 5.0  # Ignore duplicates within 5 seconds

    @property
    def plugin_name(self) -> str:
        return "irc_handler"

    async def start(self):
        """Initialize IRC connection when stream starts"""
        logger.info("Starting IRC handler - establishing connection...")
        success = await self._ensure_connected()
        if success:
            logger.info("IRC handler started successfully")
        else:
            logger.error("IRC handler failed to start - connection failed")

    @property
    def plugin_metadata(self) -> Dict[str, Any]:
        return {
            "display_name": "IRC CoT Handler",
            "description": "Receive CoT messages from TAK and post to IRC",
            "icon": "fa-comments",
            "category": "notification",
            "help_sections": [
                {
                    "title": "Template Variables",
                    "content": [
                        "Basic: {type}, {uid}, {time}, {stale}, {callsign}, {remarks}",
                        "Location: {lat}, {lon}, {hae}, {mgrs}",
                        "Group: {group_name}, {group_role}",
                        "Device: {device}, {platform}, {os}, {version}, {battery}",
                        "Track: {speed}, {course}, {xmpp_username}",
                    ],
                },
                {
                    "title": "Common CoT Types & Example Templates",
                    "content": [
                        "Chat (b-t-f): \"[CHAT] {callsign}: {remarks}\"",
                        "Emergency (b-a-o-tbl): \"[EMERGENCY] {callsign} at {mgrs}\"",
                        "Geofence Alert (b-a-o-can): \"[ALERT] {callsign} {remarks} at {lat},{lon}\"",
                        "Friendly Position (a-f-G-E-V): \"[{group_name}] {callsign} ({group_role}) - Battery: {battery}%\"",
                        "Hostile (a-h-*): \"[HOSTILE] {type} at {mgrs}\"",
                        "Ring of Fire (b-a-o-opn): \"[ROF] {callsign}: {remarks}\"",
                    ],
                },
                {
                    "title": "UID Filtering",
                    "content": [
                        "Global UID Filter: Applied before message rules (legacy, optional)",
                        "Per-Rule UID Filter: Each rule can have its own UID filter (recommended)",
                        "Example: \"^ANDROID-.*\" matches only Android devices",
                        "Example: \"^.*-Team[1-3]$\" matches Team 1-3 devices",
                        "Rules are evaluated in order; first matching rule wins",
                    ],
                },
                {
                    "title": "Important Notes",
                    "content": [
                        "At least one message rule is required for messages to be sent",
                        "Use wildcards (*) in CoT type patterns for broader matching",
                        "Messages are deduplicated within 5 seconds to avoid duplicates",
                        "IRC messages are split automatically if longer than 400 characters",
                    ],
                },
            ],
            "config_fields": [
                PluginConfigField(
                    name="server",
                    label="IRC Server",
                    field_type="text",
                    required=True,
                    placeholder="irc.libera.chat",
                    help_text="IRC server hostname",
                    row_group="irc_row_1",
                ),
                PluginConfigField(
                    name="port",
                    label="IRC Port",
                    field_type="number",
                    required=True,
                    default_value=6667,
                    min_value=1,
                    max_value=65535,
                    help_text="IRC server port (6667 for plain, 6697 for SSL)",
                    row_group="irc_row_1",
                ),
                PluginConfigField(
                    name="use_ssl",
                    label="Use SSL/TLS",
                    field_type="select",
                    required=True,
                    default_value="false",
                    options=[
                        {"value": "true", "label": "Yes"},
                        {"value": "false", "label": "No"},
                    ],
                    help_text="Enable SSL/TLS encryption",
                    row_group="irc_row_2",
                ),
                PluginConfigField(
                    name="verify_ssl",
                    label="Verify SSL Certificate",
                    field_type="select",
                    required=True,
                    default_value="true",
                    options=[
                        {"value": "true", "label": "Yes (Recommended)"},
                        {"value": "false", "label": "No (Allow Self-Signed)"},
                    ],
                    help_text="Disable only for self-signed certificates in trusted environments",
                    row_group="irc_row_2",
                ),
                PluginConfigField(
                    name="nickname",
                    label="Nickname",
                    field_type="text",
                    required=True,
                    placeholder="TrakBridge",
                    help_text="IRC bot nickname",
                    row_group="irc_row_3",
                ),
                PluginConfigField(
                    name="channel",
                    label="Channel",
                    field_type="text",
                    required=True,
                    placeholder="#tak-alerts",
                    help_text="IRC channel to join (include #)",
                    row_group="irc_row_3",
                ),
                PluginConfigField(
                    name="password",
                    label="Server Password (optional)",
                    field_type="password",
                    required=False,
                    sensitive=True,
                    help_text="IRC server password (if required)",
                    row_group="irc_row_4",
                ),
                # Note: global_geofence_enabled, global_geofence_bounds, and message_rules
                # are handled by custom UI sections (irc-global-geofence-section and irc-message-rules-section)
                # and should NOT be rendered as standard plugin config fields
                PluginConfigField(
                    name="uid_filter",
                    label="Global UID Filter (regex)",
                    field_type="text",
                    placeholder="^ANDROID-.*",
                    help_text="Global pre-filter applied before message rules (optional). See Help section for details and examples.",
                    row_group="irc_row_4",
                ),
            ],
            "custom_components": [
                PluginCustomComponent(
                    type="message_rules",
                    field_name="message_rules",
                    title="Message Rules",
                    icon="fa-filter",
                    help_text="Define rules to filter and format CoT messages before sending to IRC. Rules are evaluated in order; first matching rule wins.",
                    config={
                        "template_variables": [
                            "{type}", "{uid}", "{time}", "{stale}", "{callsign}", "{remarks}",
                            "{lat}", "{lon}", "{hae}", "{mgrs}",
                            "{group_name}", "{group_role}",
                            "{device}", "{platform}", "{os}", "{version}", "{battery}",
                            "{speed}", "{course}", "{xmpp_username}"
                        ],
                        "rule_fields": [
                            {
                                "name": "cot_type_pattern",
                                "label": "CoT Type Pattern",
                                "type": "text",
                                "required": True,
                                "placeholder": "b-t-f or a-f-* (wildcards supported)",
                                "help": "Pattern to match CoT types (e.g., b-t-f for chat, a-f-* for all friendly)"
                            },
                            {
                                "name": "uid_filter",
                                "label": "UID Filter (regex)",
                                "type": "text",
                                "required": False,
                                "placeholder": "^ANDROID-.*",
                                "help": "Optional regex to filter by UID (e.g., ^ANDROID-.* for Android devices)"
                            },
                            {
                                "name": "format_template",
                                "label": "Format Template",
                                "type": "textarea",
                                "required": True,
                                "placeholder": "[CHAT] {callsign}: {remarks}",
                                "help": "Message format using template variables above"
                            }
                        ]
                    }
                ),
                PluginCustomComponent(
                    type="geofence",
                    field_name="global_geofence",
                    title="Geofence",
                    icon="fa-map-marked-alt",
                    help_text="Filter messages by geographic bounds. Only messages within the defined area will be sent to IRC.",
                    config={
                        "default_center": [40.7, -74.0],
                        "default_zoom": 10,
                        "enable_checkbox_label": "Enable Geofence Filtering"
                    }
                )
            ],
        }

    async def _ensure_connected(self) -> bool:
        """Ensure IRC connection is established"""
        async with self._connection_lock:
            if self._connected and self._writer and not self._writer.is_closing():
                return True

            try:
                config = self.get_decrypted_config()
                server = config.get("server")
                port = int(config.get("port", 6667))
                use_ssl = config.get("use_ssl", "false").lower() == "true"
                nickname = config.get("nickname", "TrakBridge")
                password = config.get("password")
                channel = config.get("channel")

                if not server or not channel:
                    logger.error("IRC server or channel not configured")
                    return False

                # Connect to IRC server
                if use_ssl:
                    import ssl

                    ssl_context = ssl.create_default_context()

                    # Allow disabling certificate verification for self-signed certs
                    verify_ssl = config.get("verify_ssl", "true").lower() == "true"
                    if not verify_ssl:
                        logger.warning(
                            f"SSL certificate verification DISABLED for {server}:{port} - "
                            f"use only with trusted servers"
                        )
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                    self._reader, self._writer = await asyncio.open_connection(
                        server, port, ssl=ssl_context
                    )
                else:
                    self._reader, self._writer = await asyncio.open_connection(
                        server, port
                    )

                logger.info(f"Connected to IRC server {server}:{port}")

                # Perform IRC handshake
                if password:
                    self._writer.write(f"PASS {password}\r\n".encode())
                    await self._writer.drain()

                self._writer.write(f"NICK {nickname}\r\n".encode())
                self._writer.write(f"USER {nickname} 0 * :TrakBridge Bot\r\n".encode())
                await self._writer.drain()

                # Start background task to handle server messages (PING/PONG)
                # This must start BEFORE we wait for welcome, so it can receive it
                if self._reader_task is None or self._reader_task.done():
                    self._reader_task = asyncio.create_task(self._handle_irc_messages())

                # Wait for IRC handshake to complete (look for 001 welcome message)
                logger.debug("Waiting for IRC handshake to complete...")
                for _ in range(20):  # Wait up to 10 seconds
                    if self._connected:
                        break
                    await asyncio.sleep(0.5)
                else:
                    logger.error("IRC handshake timeout - no welcome message received")
                    return False

                # Now join channel
                self._writer.write(f"JOIN {channel}\r\n".encode())
                await self._writer.drain()

                # Wait a moment for join confirmation
                await asyncio.sleep(1)

                logger.info(f"Joined IRC channel {channel}")
                return True

            except Exception as e:
                logger.error(f"Failed to connect to IRC: {e}")
                self._connected = False
                if self._writer:
                    self._writer.close()
                    await self._writer.wait_closed()
                return False

    async def _handle_irc_messages(self):
        """Background task to handle IRC server messages (especially PING/PONG)"""
        logger.debug("IRC message handler task started")
        try:
            while self._reader:
                try:
                    logger.debug("Waiting for IRC server message...")
                    line = await asyncio.wait_for(self._reader.readline(), timeout=300)
                    if not line:
                        logger.warning("IRC connection closed by server")
                        self._connected = False
                        break

                    message = line.decode('utf-8', errors='ignore').strip()
                    logger.debug(f"IRC server message: {message}")

                    # Check for welcome/registration complete indicators
                    # 001 = RPL_WELCOME, 376 = RPL_ENDOFMOTD, 422 = ERR_NOMOTD
                    # Any of these indicate successful registration
                    if ' 001 ' in message or ' 376 ' in message or ' 422 ' in message:
                        if not self._connected:
                            logger.info("IRC handshake complete - registration successful")
                            self._connected = True

                    # Handle PING from server
                    if message.startswith('PING'):
                        pong_response = message.replace('PING', 'PONG', 1)
                        self._writer.write(f"{pong_response}\r\n".encode())
                        await self._writer.drain()
                        logger.debug(f"Responded to PING with: {pong_response}")

                    # Log other important messages
                    elif 'ERROR' in message:
                        logger.error(f"IRC error: {message}")

                except asyncio.TimeoutError:
                    # No message in 5 minutes - send a PING to check connection
                    if self._writer and not self._writer.is_closing():
                        try:
                            self._writer.write(b"PING :keepalive\r\n")
                            await self._writer.drain()
                            logger.debug("Sent keepalive PING")
                        except Exception as e:
                            logger.error(f"Failed to send keepalive: {e}")
                            self._connected = False
                            break

                except Exception as e:
                    logger.error(f"Error reading IRC message: {e}")
                    await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"IRC message handler crashed: {e}")
            self._connected = False
        finally:
            logger.debug("IRC message handler task exiting")

    async def handle_cot_message(self, cot_xml: bytes, tak_server_id: int) -> None:
        """Parse CoT and send to IRC if it matches our filters"""

        logger.debug(f"IRCHandler received CoT message from TAK server {tak_server_id}, size: {len(cot_xml)} bytes")
        logger.debug(f"CoT XML preview: {cot_xml}")

        # Ensure we're connected before processing (reconnect if needed)
        if not await self._ensure_connected():
            logger.error("Cannot process CoT message - IRC connection failed")
            return

        try:
            # Parse XML securely
            root = DefusedET.fromstring(cot_xml)

            # Extract fields
            cot_type = root.get("type", "")
            uid = root.get("uid", "")

            logger.debug(f"Parsed CoT: type={cot_type}, uid={uid}")

            # Extract lat/lon for future geofence filtering
            point = root.find("point")
            lat = ""
            lon = ""
            if point is not None:
                lat = point.get("lat", "")
                lon = point.get("lon", "")

            # Apply plugin's own filters and get template
            should_handle, template = self._should_handle(cot_type, uid, lat, lon)
            if not should_handle:
                logger.debug(f"Filtered out: type={cot_type}, uid={uid} (does not match any rules)")
                return

            logger.info(f"CoT passed filters, processing: type={cot_type}, uid={uid}")

            # Deduplication: check if we've seen this UID+type combo recently
            # Don't include time in key since TAK server may update timestamp on rebroadcast
            dedup_key = f"{uid}:{cot_type}"
            now = time.time()

            # Clean up old entries
            self._seen_messages = {
                k: v for k, v in self._seen_messages.items()
                if now - v < self._dedup_ttl_seconds
            }

            if dedup_key in self._seen_messages:
                time_since_last = now - self._seen_messages[dedup_key]
                logger.debug(f"Duplicate message ignored: {dedup_key} (seen {time_since_last:.2f}s ago)")
                return

            self._seen_messages[dedup_key] = now
            logger.debug(f"New message accepted: {dedup_key}")

            # Extract template variables
            variables = self._extract_template_variables(root)

            # Format message using template
            if template:
                msg = self._format_message(template, variables)
            else:
                # Fallback to default format if no template
                msg = f"[{cot_type}] {variables['callsign']}"

            logger.info(f"Sending formatted message to IRC: {msg}")
            await self._send_to_irc(msg)

        except Exception as e:
            logger.error(f"IRCHandler failed to process CoT: {e}")

    def _matches_cot_pattern(self, cot_type: str, pattern: str) -> bool:
        """Check if CoT type matches pattern (supports wildcards)"""
        if pattern.endswith("*"):
            # Wildcard match
            return cot_type.startswith(pattern[:-1])
        else:
            # Exact match
            return cot_type == pattern

    def _extract_template_variables(self, root) -> Dict[str, str]:
        """Extract template variables from CoT XML"""
        variables = {
            "type": root.get("type", ""),
            "uid": root.get("uid", ""),
            "time": root.get("time", ""),
            "stale": root.get("stale", ""),
            "callsign": "Unknown",
            "lat": "",
            "lon": "",
            "hae": "",
            "mgrs": "",
            "remarks": "",
            "group_name": "",
            "group_role": "",
            "battery": "",
            "device": "",
            "platform": "",
            "os": "",
            "version": "",
            "speed": "",
            "course": "",
            "xmpp_username": "",
        }

        # Extract point data
        point = root.find("point")
        if point is not None:
            variables["lat"] = point.get("lat", "")
            variables["lon"] = point.get("lon", "")
            variables["hae"] = point.get("hae", "")
            logger.debug(f"Extracted point data: lat={variables['lat']}, lon={variables['lon']}, hae={variables['hae']}")

            # Convert to MGRS if we have valid coordinates
            if variables["lat"] and variables["lon"]:
                try:
                    lat_float = float(variables["lat"])
                    lon_float = float(variables["lon"])
                    m = mgrs.MGRS()
                    variables["mgrs"] = m.toMGRS(lat_float, lon_float)
                    logger.debug(f"Converted to MGRS: {variables['mgrs']}")
                except (ValueError, Exception) as e:
                    logger.warning(f"Failed to convert lat/lon to MGRS: {e}")
                    variables["mgrs"] = ""
            else:
                variables["mgrs"] = ""
        else:
            logger.debug("No point element found in CoT XML")
            variables["mgrs"] = ""

        # Extract detail data
        detail = root.find("detail")
        if detail is not None:
            contact = detail.find("contact")
            if contact is not None:
                variables["callsign"] = contact.get("callsign", "Unknown")
                variables["xmpp_username"] = contact.get("xmppUsername", "")

            remarks = detail.find("remarks")
            if remarks is not None and remarks.text:
                variables["remarks"] = remarks.text

            # Extract group data from __group element
            group = detail.find("__group")
            if group is not None:
                variables["group_name"] = group.get("name", "")
                variables["group_role"] = group.get("role", "")

            # Extract battery from status element
            status = detail.find("status")
            if status is not None:
                variables["battery"] = status.get("battery", "")

            # Extract device info from takv element
            takv = detail.find("takv")
            if takv is not None:
                variables["device"] = takv.get("device", "")
                variables["platform"] = takv.get("platform", "")
                variables["os"] = takv.get("os", "")
                variables["version"] = takv.get("version", "")

            # Extract track data from track element
            track = detail.find("track")
            if track is not None:
                variables["speed"] = track.get("speed", "")
                variables["course"] = track.get("course", "")

        return variables

    def _format_message(self, template: str, variables: Dict[str, str]) -> str:
        """Format message using template and variables"""
        try:
            return template.format(**variables)
        except KeyError as e:
            logger.warning(f"Template variable missing: {e}")
            return f"{template} [ERROR: missing variable {e}]"
        except Exception as e:
            logger.error(f"Template formatting error: {e}")
            return f"{template} [ERROR: {e}]"

    def _is_within_geofence(self, lat: str, lon: str, bounds: dict) -> bool:
        """Check if coordinates are within bounding box"""
        try:
            lat_float = float(lat)
            lon_float = float(lon)

            north = float(bounds.get("north", 90))
            south = float(bounds.get("south", -90))
            east = float(bounds.get("east", 180))
            west = float(bounds.get("west", -180))

            # Simple bounding box check
            lat_ok = south <= lat_float <= north
            lon_ok = west <= lon_float <= east

            logger.debug(f"Geofence check: lat={lat_float} in [{south}, {north}]? {lat_ok}, lon={lon_float} in [{west}, {east}]? {lon_ok}")

            return lat_ok and lon_ok

        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid coordinates or bounds for geofence check: {e}")
            return True  # Fail open - don't filter if we can't validate

    def _should_handle(self, cot_type: str, uid: str, lat: str = "", lon: str = "") -> tuple[bool, str]:
        """Plugin-specific filtering logic - returns (should_handle, template)"""
        config = self.get_decrypted_config()

        logger.debug(f"_should_handle called with cot_type={cot_type}, uid={uid}, lat={lat}, lon={lon}")

        # Global UID filter (optional pre-filter, for backwards compatibility)
        global_uid_filter = config.get("uid_filter", "")
        if global_uid_filter:
            logger.debug(f"Global UID filter configured: '{global_uid_filter}'")
            try:
                if not re.match(global_uid_filter, uid):
                    logger.debug(f"UID '{uid}' does not match global filter '{global_uid_filter}'")
                    return (False, "")
                logger.debug(f"UID '{uid}' matches global filter '{global_uid_filter}'")
            except re.error:
                logger.error(f"Invalid global UID filter regex: {global_uid_filter}")
                return (False, "")

        # Check geofence before matching rules
        global_geofence_enabled = config.get("global_geofence_enabled", "false") == "true"
        global_geofence_bounds = config.get("global_geofence_bounds", {})

        if global_geofence_enabled and global_geofence_bounds and lat and lon:
            if not self._is_within_geofence(lat, lon, global_geofence_bounds):
                logger.debug(f"Filtered out by geofence: lat={lat}, lon={lon}")
                return (False, "")
            logger.debug("Passed geofence check")

        # Check message rules
        message_rules = config.get("message_rules", [])
        logger.debug(f"Message rules configured: {message_rules}")
        if not message_rules:
            # No rules configured - don't handle any messages
            logger.debug("No message rules configured - rejecting")
            return (False, "")

        # Find first matching rule
        for rule in message_rules:
            logger.debug(f"Checking rule: {rule}")
            if not rule.get("enabled", True):
                logger.debug("Rule is disabled, skipping")
                continue

            # Check rule-level UID filter first (if specified)
            rule_uid_filter = rule.get("uid_filter", "")
            if rule_uid_filter:
                try:
                    if not re.match(rule_uid_filter, uid):
                        logger.debug(f"UID '{uid}' does not match rule filter '{rule_uid_filter}'")
                        continue  # Try next rule
                    logger.debug(f"UID '{uid}' matches rule filter '{rule_uid_filter}'")
                except re.error:
                    logger.error(f"Invalid rule UID filter regex: {rule_uid_filter}")
                    continue  # Try next rule

            pattern = rule.get("cot_type_pattern", "")
            logger.debug(f"Checking pattern '{pattern}' against cot_type '{cot_type}'")
            if pattern and self._matches_cot_pattern(cot_type, pattern):
                template = rule.get("format_template", "")
                logger.debug(f"Pattern matched! Using template: {template}")
                return (True, template)

        # No matching rule
        return (False, "")

    @staticmethod
    def _sanitize_irc_payload(text: str) -> str:
        """Strip CR/LF (and NUL) from a value before it hits the IRC wire.

        T5.2: IRC uses `\\r\\n` as a command separator. Untrusted CoT-derived
        fields (callsign, remarks, group name) flow through the message
        template unmodified; a value like `alice\\r\\nJOIN #evil` would let
        an attacker inject arbitrary IRC commands with the bot's privileges.
        Replace CR/LF with a single space, drop NUL bytes entirely.
        """
        if not text:
            return text
        return (
            text.replace("\r\n", " ")
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("\x00", "")
        )

    async def _send_to_irc(self, message: str):
        """Send message to IRC channel"""
        config = self.get_decrypted_config()
        channel = config.get("channel")

        if not channel:
            return

        # Check if connected, but don't try to connect here
        if not self._connected or not self._writer or self._writer.is_closing():
            logger.warning("Cannot send to IRC: not connected. Connection should be established at stream start.")
            return

        # T5.2: sanitise once at the chokepoint. Any embedded CR/LF in
        # the message body or the channel name would let an attacker
        # inject IRC commands.
        safe_message = self._sanitize_irc_payload(message)
        safe_channel = self._sanitize_irc_payload(channel)

        try:
            # Send message (split long messages if needed)
            max_length = 400  # IRC message length limit
            for i in range(0, len(safe_message), max_length):
                chunk = safe_message[i : i + max_length]
                self._writer.write(
                    f"PRIVMSG {safe_channel} :{chunk}\r\n".encode()
                )
                await self._writer.drain()
                logger.debug(f"Sent message to IRC: {chunk}")

        except Exception as e:
            logger.error(f"Failed to send to IRC: {e}")
            self._connected = False

    async def test_connection(self) -> Dict[str, Any]:
        """Test IRC connection"""
        config = self.get_decrypted_config()

        # Validate required fields
        required_fields = ["server", "port", "nickname", "channel"]
        for field in required_fields:
            if not config.get(field):
                return {
                    "success": False,
                    "error": f"Missing required field: {field}",
                    "message": f"Please configure {field}",
                }

        try:
            # Attempt to connect
            if await self._ensure_connected():
                # Send test message
                await self._send_to_irc("[TrakBridge] Connection test successful")

                return {
                    "success": True,
                    "message": f"Successfully connected to {config.get('server')} and joined {config.get('channel')}",
                }
            else:
                return {
                    "success": False,
                    "error": "Connection failed",
                    "message": "Failed to connect to IRC server or join channel",
                }

        except Exception as e:
            logger.error(f"IRCHandler connection test failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "message": "Connection test failed",
            }

    async def cleanup(self):
        """Cleanup IRC connection"""
        # Cancel background tasks
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass

        # Close connection gracefully
        if self._writer and not self._writer.is_closing():
            try:
                config = self.get_decrypted_config()
                channel = config.get("channel")
                if channel:
                    self._writer.write(f"PART {channel}\r\n".encode())
                    await self._writer.drain()
                self._writer.write(b"QUIT :TrakBridge shutting down\r\n")
                await self._writer.drain()
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as e:
                logger.error(f"Error cleaning up IRC connection: {e}")
        self._connected = False
