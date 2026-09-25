# ABOUTME: UDP multicast → TAK CoT bridge. Joins a multicast group, accepts
# ABOUTME: CoT XML and/or TAK Protocol v1 (Mesh SA protobuf), forwards to TAK.

import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import quoteattr

import takproto
from defusedxml import ElementTree as ET
from google.protobuf.message import DecodeError

from plugins.base_plugin import BaseInboundPlugin, PluginConfigField
from services.cot_service_integration import get_queued_cot_service

_STATS_FLUSH_INTERVAL = 30

_logger_instance = None


def get_logger():
    global _logger_instance
    if _logger_instance is None:
        from services.logging_service import get_module_logger

        _logger_instance = get_module_logger(__name__)
    return _logger_instance


class _LoggerProxy:
    def __getattr__(self, name):
        return getattr(get_logger(), name)


logger = _LoggerProxy()


# IP_ADD_SOURCE_MEMBERSHIP is not exposed by Python's socket module on all
# platforms; the numeric value is stable per the Linux/BSD ABI.
_IP_ADD_SOURCE_MEMBERSHIP = getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 39)


# TAK Protocol v1 Mesh SA magic prefix (see takproto src-protobuf/protocol.txt).
_TAKPROTO_MAGIC = b"\xbf\x01\xbf"


def _ms_to_cot_time(ms: int) -> str:
    """Convert milliseconds-since-Unix-epoch to Z-suffixed ISO-8601."""
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _format_number(value: float) -> str:
    """Render a float without trailing zeros while preserving precision."""
    if value == int(value):
        return str(int(value))
    return repr(value)


_NAMED_DETAIL_FIELDS = (
    # (proto field name, XML tag name, [(proto attr, XML attr), ...])
    ("contact", "contact", [("callsign", "callsign"), ("endpoint", "endpoint")]),
    (
        "group",
        "__group",
        [("name", "name"), ("role", "role")],
    ),
    (
        "precisionLocation",
        "precisionlocation",
        [("geopointsrc", "geopointsrc"), ("altsrc", "altsrc")],
    ),
    ("status", "status", [("battery", "battery")]),
    (
        "takv",
        "takv",
        [
            ("device", "device"),
            ("platform", "platform"),
            ("os", "os"),
            ("version", "version"),
        ],
    ),
    ("track", "track", [("speed", "speed"), ("course", "course")]),
)


def _emit_named_detail(detail) -> str:
    """Serialise the structured Detail submessages to XML fragments."""
    out = []
    for proto_field, xml_tag, attrs in _NAMED_DETAIL_FIELDS:
        if not detail.HasField(proto_field):
            continue
        sub = getattr(detail, proto_field)
        attr_str = []
        for proto_attr, xml_attr in attrs:
            raw = getattr(sub, proto_attr)
            if raw in (None, "", 0) and not isinstance(raw, float):
                # Skip default-valued scalar fields. Proto3 cannot tell
                # "unset" from "default" for scalars, so this is best-effort.
                continue
            if isinstance(raw, float):
                rendered = _format_number(raw)
            else:
                rendered = str(raw)
            attr_str.append(f"{xml_attr}={quoteattr(rendered)}")
        if attr_str:
            out.append(f"<{xml_tag} {' '.join(attr_str)}/>")
    return "".join(out)


def _takproto_to_cot_xml(datagram: bytes) -> bytes:
    """
    Decode a TAK Protocol v1 Mesh SA datagram (bf 01 bf + TakMessage protobuf)
    into a CoT <event> XML byte string. Raises ValueError on malformed input.
    """
    if not datagram.startswith(_TAKPROTO_MAGIC):
        raise ValueError("missing TAK Protocol v1 magic prefix")
    try:
        msg = takproto.parse_mesh(datagram)
    except DecodeError as exc:
        raise ValueError(f"protobuf decode failed: {exc}") from exc

    ce = msg.cotEvent
    point_attrs = " ".join(
        f"{k}={quoteattr(_format_number(v))}"
        for k, v in (
            ("lat", ce.lat),
            ("lon", ce.lon),
            ("hae", ce.hae),
            ("ce", ce.ce),
            ("le", ce.le),
        )
    )

    # Detail body: named submessages first, then xmlDetail residual.
    detail_body = _emit_named_detail(ce.detail) + (ce.detail.xmlDetail or "")
    detail_xml = f"<detail>{detail_body}</detail>" if detail_body else ""

    event_attrs = " ".join(
        f"{k}={quoteattr(v)}"
        for k, v in (
            ("version", "2.0"),
            ("uid", ce.uid),
            ("type", ce.type),
            ("how", ce.how),
            ("time", _ms_to_cot_time(ce.sendTime)),
            ("start", _ms_to_cot_time(ce.startTime)),
            ("stale", _ms_to_cot_time(ce.staleTime)),
        )
    )

    xml = f"<event {event_attrs}><point {point_attrs}/>{detail_xml}</event>"
    return xml.encode("utf-8")


class _TokenBucket:
    """Per-source token bucket. Capacity equals refill rate (1-second burst)."""

    def __init__(self, rate: int, now=time.monotonic):
        self._rate = float(rate)
        self._capacity = float(rate)
        self._tokens = float(rate)
        self._now = now
        self._last = now()

    def try_take(self) -> bool:
        current = self._now()
        elapsed = current - self._last
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last = current
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class UdpMulticastListener(BaseInboundPlugin):
    """
    Active-connect inbound plugin: joins a UDP multicast group, receives raw CoT
    XML datagrams, and forwards them verbatim to every configured TAK server via
    the existing QueuedCOTService raw-bytes injection point. No conversion.
    """

    PLUGIN_NAME = "udp_multicast_listener"
    _RATE_BUCKET_SOFT_CAP = 1024
    _DIAGNOSTIC_SAMPLE_LIMIT = 5
    _UID_COUNTER_SOFT_CAP = 256

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._socket: Optional[socket.socket] = None
        self._cot_service = None
        self._target_servers: List[Any] = []
        self._rate_buckets: Dict[str, _TokenBucket] = {}
        self._received = 0
        self._forwarded = 0
        self._dropped_validation = 0
        self._dropped_rate = 0
        self._dropped_size = 0
        # Per-UID forwarded counter — diagnostic for silent-drop investigation.
        # Capped to bound memory if the multicast group has many distinct UIDs.
        self._forwarded_by_uid: Dict[str, int] = {}
        self._diagnostic_samples_logged = 0
        self._pending_stats = 0
        self._stats_last_flush: Optional[float] = None

    @property
    def plugin_name(self) -> str:
        return self.PLUGIN_NAME

    @classmethod
    def get_plugin_name(cls) -> str:
        return cls.PLUGIN_NAME

    @property
    def plugin_metadata(self) -> Dict[str, Any]:
        return {
            "display_name": "UDP Multicast CoT Bridge",
            "description": (
                "Join a UDP multicast group and forward raw CoT XML datagrams "
                "verbatim to TAK servers. Bridges LAN multicast traffic across "
                "VPN/WAN links that cannot carry multicast."
            ),
            "icon": "fa-arrow-down",
            "category": "inbound",
            "inbound_transport": "active",
            "accepted_content_types": ["application/xml"],
            "config_fields": [
                PluginConfigField(
                    name="multicast_group",
                    label="Multicast Group",
                    field_type="text",
                    required=True,
                    placeholder="239.2.3.1",
                    help_text="IPv4 multicast address (224.0.0.0/4).",
                    default_value="239.2.3.1",
                ),
                PluginConfigField(
                    name="multicast_port",
                    label="Multicast Port",
                    field_type="number",
                    required=True,
                    min_value=1,
                    max_value=65535,
                    default_value=6969,
                ),
                PluginConfigField(
                    name="bind_interface",
                    label="Bind Interface",
                    field_type="text",
                    required=False,
                    placeholder="0.0.0.0",
                    help_text=(
                        "Local IP of the interface to join the multicast "
                        "group on. Set this explicitly on multi-homed hosts "
                        "or in Docker containers with multiple networks — "
                        "0.0.0.0 tells the kernel to pick via the default "
                        "route, which in a container is usually the Docker "
                        "bridge (wrong interface for LAN multicast)."
                    ),
                    default_value="0.0.0.0",
                ),
                PluginConfigField(
                    name="source_filter",
                    label="Source Filter (SSM)",
                    field_type="text",
                    required=False,
                    placeholder="10.0.0.5, 10.0.0.6",
                    help_text=(
                        "Optional comma-separated allowlist of source IPs. "
                        "When set, uses IGMPv3 source-specific multicast (SSM) — "
                        "the kernel drops datagrams from any source not listed here "
                        "before they reach the application. This blocks spoofed or "
                        "reflected CoT injection from unauthorized senders on the "
                        "same multicast group. Accepts exact IPv4 addresses only "
                        "(not CIDRs — SSM is a kernel socket option)."
                    ),
                ),
                PluginConfigField(
                    name="max_packet_bytes",
                    label="Max Datagram Bytes",
                    field_type="number",
                    required=False,
                    min_value=1,
                    max_value=65535,
                    default_value=65535,
                    help_text="Drop datagrams larger than this size.",
                ),
                PluginConfigField(
                    name="per_source_rate_limit",
                    label="Per-Source Rate Limit (pkt/s)",
                    field_type="number",
                    required=False,
                    min_value=0,
                    default_value=200,
                    help_text="0 disables rate limiting.",
                ),
                PluginConfigField(
                    name="format",
                    label="Wire Format",
                    field_type="select",
                    required=False,
                    default_value="auto",
                    options=[
                        {
                            "value": "auto",
                            "label": "Auto-detect (XML or TAK Protocol v1)",
                        },
                        {"value": "xml", "label": "CoT XML only"},
                        {
                            "value": "takproto",
                            "label": "TAK Protocol v1 (Mesh SA protobuf) only",
                        },
                    ],
                    help_text=(
                        "ATAK/WinTAK Mesh SA sends TAK Protocol v1 protobuf "
                        "(0xbf 0x01 0xbf magic) by default. Auto-detect "
                        "decodes protobuf to CoT XML and forwards XML "
                        "verbatim."
                    ),
                ),
                PluginConfigField(
                    name="require_cot_event_root",
                    label="Validate CoT <event> root",
                    field_type="checkbox",
                    required=False,
                    default_value=True,
                    help_text=(
                        "Drop datagrams whose root element is not <event> "
                        "(XML mode) or whose magic prefix isn't 0xbf 0x01 "
                        "0xbf (takproto mode). Disable to forward all UDP "
                        "payloads verbatim."
                    ),
                ),
            ],
            "help_sections": [
                {
                    "title": "Overview",
                    "content": [
                        "Joins a UDP multicast group and forwards raw CoT XML "
                        "to every TAK server configured on the stream.",
                        "Datagrams are sent on the wire exactly as received — "
                        "no parsing, no re-serialisation.",
                        "Use case: bridging LAN multicast CoT (e.g. ATAK) over "
                        "VPN/WAN where multicast is not routed.",
                    ],
                },
                {
                    "title": "Multicast Join",
                    "content": [
                        "Bind interface controls which NIC issues the IGMP "
                        "membership; useful on multi-homed hosts.",
                        "Setting Source Filter switches to IGMPv3 source-"
                        "specific multicast — only listed senders are delivered.",
                    ],
                },
                {
                    "title": "Safety",
                    "content": [
                        "Datagrams over Max Datagram Bytes are dropped.",
                        "Per-Source Rate Limit caps packets/second per sender "
                        "to protect the TAK queue from a noisy group.",
                    ],
                },
            ],
        }

    def validate_config(self) -> bool:
        if not super().validate_config():
            return False

        import ipaddress

        # T1.2: raise ValueError (not just return False) so
        # update_stream_safely() surfaces the reason in the UI —
        # matches the T1.3 pattern. Returning False alone got swallowed
        # by the save-time hook, letting invalid configs persist.
        group = str(self.config.get("multicast_group", "") or "")
        if group:
            try:
                addr = ipaddress.ip_address(group)
                if not addr.is_multicast:
                    raise ValueError(
                        f"Multicast Group '{group}' is not a multicast "
                        "address. Use an IPv4 address in 224.0.0.0/4 "
                        "(for example 239.2.3.1)."
                    )
            except ValueError as e:
                # ip_address() raises ValueError for malformed input;
                # our own raise above lands here too. Re-raise with a
                # user-readable message.
                if "is not a multicast address" in str(e):
                    raise
                raise ValueError(
                    f"Multicast Group '{group}' is not a valid IP address."
                )

        source_filter = str(self.config.get("source_filter") or "")
        if source_filter.strip():
            for entry in source_filter.replace(",", "\n").splitlines():
                entry = entry.strip()
                if not entry:
                    continue
                try:
                    ipaddress.ip_address(entry)
                except ValueError:
                    raise ValueError(
                        f"Source Filter entry '{entry}' is not a valid "
                        "IPv4 address. SSM requires exact source IPs, "
                        "not CIDR blocks — for example "
                        "'10.0.0.5, 10.0.0.6'."
                    )

        return True

    def transform_payload(self, raw_body, content_type, headers):
        raise NotImplementedError(
            f"{self.__class__.__name__} uses an active multicast listener, "
            "not HTTP push"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        config = self.get_decrypted_config()
        self._cot_service = get_queued_cot_service()

        servers = []
        if self.stream is not None:
            try:
                servers = list(self.stream.get_active_tak_servers() or [])
            except Exception as exc:
                logger.error(f"UDP multicast: failed to list TAK servers: {exc}")
                servers = []
        self._target_servers = servers

        if not servers:
            logger.warning(
                "UDP multicast: no active TAK servers for stream — listener "
                "will not open until servers are configured"
            )
            return

        for server in servers:
            try:
                await self._cot_service.start_worker(server)
            except Exception as exc:
                logger.error(
                    f"UDP multicast: failed to start worker for TAK "
                    f"server {getattr(server, 'name', '?')}: {exc}"
                )

        self._socket = self._open_socket(config)

        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), sock=self._socket
        )
        logger.info(
            f"UDP multicast listener joined "
            f"{config.get('multicast_group')}:{config.get('multicast_port')}"
        )

    async def cleanup(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception as exc:
                logger.debug(f"UDP multicast: transport close error: {exc}")
            self._transport = None
        self._socket = None
        self._flush_stats()
        logger.info(
            f"UDP multicast listener stopped — received={self._received}, "
            f"forwarded={self._forwarded}, dropped_validation="
            f"{self._dropped_validation}, dropped_rate={self._dropped_rate}, "
            f"dropped_size={self._dropped_size}"
        )
        # Per-UID totals help diagnose silent drops further downstream: compare
        # these against TX loop's per-UID write counters and TAK Server's
        # "Processed" count for each subscription.
        if self._forwarded_by_uid:
            top = sorted(
                self._forwarded_by_uid.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )[:10]
            summary = ", ".join(f"{uid}={count}" for uid, count in top)
            logger.info(
                f"UDP multicast forwarded-per-uid (top {len(top)} of "
                f"{len(self._forwarded_by_uid)}): {summary}"
            )

    # ------------------------------------------------------------------
    # Socket
    # ------------------------------------------------------------------

    def _open_socket(self, config: Dict[str, Any]) -> socket.socket:
        group = str(config.get("multicast_group", "239.2.3.1"))
        port = int(config.get("multicast_port", 6969))
        bind_iface = str(config.get("bind_interface") or "0.0.0.0")
        sources = [
            s.strip()
            for s in str(config.get("source_filter") or "").split(",")
            if s.strip()
        ]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_REUSEPORT lets several listeners share the port on platforms that
        # support it (Linux, macOS, *BSD); harmless if unavailable.
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

        # Bind to INADDR_ANY (not `bind_iface`). A socket bound to a specific
        # unicast IP filters incoming datagrams by destination address, and
        # multicast frames are destined for the group IP (239.x.x.x), not the
        # interface IP — so binding to `bind_iface` silently drops all
        # multicast delivery even though the IGMP join succeeds. Instead, use
        # `bind_iface` only to hint which interface receives the IGMP report:
        # the kernel uses the IP in `mreq` to pick the interface, and delivers
        # multicast frames received on that interface up to this socket.
        sock.bind(("", port))
        sock.setblocking(False)

        group_packed = socket.inet_aton(group)
        iface_packed = socket.inet_aton(bind_iface)

        if sources:
            for src in sources:
                mreq = group_packed + iface_packed + socket.inet_aton(src)
                sock.setsockopt(socket.IPPROTO_IP, _IP_ADD_SOURCE_MEMBERSHIP, mreq)
        else:
            mreq = group_packed + iface_packed
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        return sock

    # ------------------------------------------------------------------
    # Validation & rate limit
    # ------------------------------------------------------------------

    def _is_cot_event(self, data: bytes) -> bool:
        if not data:
            return False
        # ATAK/WinTAK and other CoT senders sometimes wrap datagrams with a
        # leading XML declaration, BOM, or pad them to a fixed buffer with
        # trailing NUL bytes. Trim those before parsing.
        trimmed = data.lstrip(b"\x00 \t\r\n\xef\xbb\xbf").rstrip(b"\x00 \t\r\n")
        if not trimmed:
            return False
        try:
            root = ET.fromstring(trimmed)
        except (ET.ParseError, ValueError):
            return False
        # Strip any XML namespace from the tag before comparing.
        tag = root.tag.rsplit("}", 1)[-1] if isinstance(root.tag, str) else ""
        return tag == "event"

    def _rate_allowed(self, source_ip: str) -> bool:
        rate = int(self.config.get("per_source_rate_limit", 200) or 0)
        if rate <= 0:
            return True
        bucket = self._rate_buckets.get(source_ip)
        if bucket is None:
            if len(self._rate_buckets) >= self._RATE_BUCKET_SOFT_CAP:
                # Evict an arbitrary entry to bound memory under wide source
                # fan-out; a smarter LRU would be overkill for the soft cap.
                self._rate_buckets.pop(next(iter(self._rate_buckets)))
            bucket = _TokenBucket(rate)
            self._rate_buckets[source_ip] = bucket
        return bucket.try_take()

    def _log_drop_sample(self, source_ip: str, reason: str, data: bytes) -> None:
        if self._diagnostic_samples_logged < self._DIAGNOSTIC_SAMPLE_LIMIT:
            self._diagnostic_samples_logged += 1
            logger.warning(
                f"UDP multicast: dropped datagram from {source_ip} "
                f"({reason}, {len(data)} bytes): {data[:200]!r}"
            )

    def _convert(self, data: bytes, source_ip: str) -> Optional[bytes]:
        """
        Resolve the wire format, validate, and return the bytes that should be
        enqueued for TAK servers. Returns None when the datagram is dropped
        (counters and diagnostic logs handled here).
        """
        fmt = str(self.config.get("format", "auto")).lower()
        require_validation = bool(self.config.get("require_cot_event_root", True))

        is_takproto = data.startswith(_TAKPROTO_MAGIC)

        if fmt == "takproto" or (fmt == "auto" and is_takproto):
            if not is_takproto:
                if require_validation:
                    self._dropped_validation += 1
                    self._log_drop_sample(source_ip, "expected takproto", data)
                    return None
                return data
            try:
                return _takproto_to_cot_xml(data)
            except ValueError as exc:
                self._dropped_validation += 1
                self._log_drop_sample(source_ip, f"takproto decode failed: {exc}", data)
                return None

        # XML path (fmt == "xml" or auto-with-no-magic).
        if require_validation and not self._is_cot_event(data):
            self._dropped_validation += 1
            self._log_drop_sample(source_ip, "not a CoT <event>", data)
            return None
        return data

    # ------------------------------------------------------------------
    # Datagram handling
    # ------------------------------------------------------------------

    async def _handle_datagram(self, data: bytes, addr) -> None:
        self._received += 1

        max_bytes = int(self.config.get("max_packet_bytes", 65535) or 65535)
        if len(data) > max_bytes:
            self._dropped_size += 1
            return

        source_ip = addr[0] if isinstance(addr, tuple) and addr else "0.0.0.0"
        if not self._rate_allowed(source_ip):
            self._dropped_rate += 1
            return

        outbound = self._convert(data, source_ip)
        if outbound is None:
            return

        if not self._target_servers or self._cot_service is None:
            return

        # Extract UID once so per-UID counters can attribute the forward.
        # If extraction fails (post-conversion this should be rare), we still
        # forward; the global _forwarded counter still increments.
        uid = self._extract_uid(outbound)

        for server in self._target_servers:
            try:
                ok = await self._cot_service.enqueue_event(outbound, server.id)
                if ok:
                    self._forwarded += 1
                    self._pending_stats += 1
                    if uid:
                        self._bump_uid_counter(uid)
            except Exception as exc:
                logger.error(
                    f"UDP multicast: enqueue failed for TAK server "
                    f"{getattr(server, 'name', '?')}: {exc}"
                )

        self._flush_stats_if_needed()

    def _extract_uid(self, event: bytes) -> str:
        """Pull the event UID for per-UID diagnostics. Returns '' on failure."""
        try:
            root = ET.fromstring(event)
        except (ET.ParseError, ValueError):
            return ""
        return root.get("uid") or ""

    def _bump_uid_counter(self, uid: str) -> None:
        """Increment per-UID forwarded counter under a soft memory cap."""
        if uid in self._forwarded_by_uid:
            self._forwarded_by_uid[uid] += 1
            return
        if len(self._forwarded_by_uid) >= self._UID_COUNTER_SOFT_CAP:
            # Evict an arbitrary entry; this counter is diagnostic, not exact.
            self._forwarded_by_uid.pop(next(iter(self._forwarded_by_uid)))
        self._forwarded_by_uid[uid] = 1

    def _flush_stats(self) -> None:
        """Persist accumulated forwarded count to the stream's DB record."""
        if self._pending_stats == 0 or self.stream is None:
            return
        try:
            from database import db
            from models.stream import Stream

            stream_id = getattr(self.stream, "id", None)
            if stream_id is None:
                return
            stream = db.session.get(Stream, stream_id)
            if stream:
                stream.update_stats(messages_sent=self._pending_stats)
                db.session.commit()
        except Exception as exc:
            logger.warning(f"UDP multicast: failed to flush stats: {exc}")
            try:
                from database import db
                db.session.rollback()
            except Exception:
                pass
        finally:
            self._pending_stats = 0
            self._stats_last_flush = time.monotonic()

    def _flush_stats_if_needed(self) -> None:
        now = time.monotonic()
        if self._stats_last_flush is None or (now - self._stats_last_flush) >= _STATS_FLUSH_INTERVAL:
            self._flush_stats()


class _Protocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol bridging socket reads to the plugin."""

    def __init__(self, plugin: UdpMulticastListener):
        self._plugin = plugin

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.create_task(self._plugin._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.warning(f"UDP multicast: socket error: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            logger.warning(f"UDP multicast: connection lost: {exc}")
