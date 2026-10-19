"""
ABOUTME: HTTP endpoint for receiving push data from external devices,
ABOUTME: converting to CoT XML via inbound plugins, and distributing to TAK.
"""

import asyncio
import ipaddress
import json
import logging
import math
import threading
import time
from typing import Dict, List

from flask import Blueprint, jsonify, request

from database import db
from models.stream import Stream
from plugins.plugin_manager import get_plugin_manager
from services.auth import require_permission
from services.auth.decorators import api_key_or_auth_required
from services.inbound_stream_worker import get_active_inbound_streams

logger = logging.getLogger(__name__)

bp = Blueprint("inbound", __name__)

# Limits
MAX_PAYLOAD_BYTES = 1_048_576  # 1 MB
MAX_LOCATIONS_PER_REQUEST = 100

# Anti-enumeration: same response for not-found/auth-fail/inactive/wrong-mode
_NOT_FOUND_RESPONSE = {"error": "Not found"}, 404

# Per-stream sliding-window rate limiter (stream_id → request timestamps)
_rate_limit_buckets: Dict[int, List[float]] = {}
_rate_limit_lock = threading.Lock()


def _is_rate_limited(stream_id: int, max_requests_per_minute: int) -> bool:
    """
    Check if a stream has exceeded its configured rate limit using a
    sliding 60-second window.

    Returns True if the request should be rejected.
    """
    if not max_requests_per_minute or max_requests_per_minute <= 0:
        return False

    now = time.monotonic()
    window_start = now - 60.0

    with _rate_limit_lock:
        timestamps = _rate_limit_buckets.get(stream_id, [])
        # Prune timestamps outside the window
        timestamps = [t for t in timestamps if t > window_start]

        if len(timestamps) >= max_requests_per_minute:
            _rate_limit_buckets[stream_id] = timestamps
            return True

        timestamps.append(now)
        _rate_limit_buckets[stream_id] = timestamps
        return False


def _mask_api_key(key: str) -> str:
    """Mask API key for safe logging, showing only last 4 chars."""
    if not key or len(key) <= 4:
        return "****"
    return f"****{key[-4:]}"


def _parse_ip_allowlist(raw: str) -> List[str]:
    """Parse an allowlist config value into a list of IP/CIDR strings.

    Accepts either legacy JSON array format (['10.0.0.0/8', ...]) or
    newline/comma-separated free text (the format the UI now exposes).
    JSON is tried first for backward compatibility with existing configs.
    """
    if not raw:
        return []
    text = raw.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if str(x).strip()]
    except (json.JSONDecodeError, ValueError):
        pass
    return [
        token.strip()
        for token in text.replace(",", "\n").splitlines()
        if token.strip()
    ]


def _check_ip_allowlist(allowlist_raw: str, remote_addr: str) -> bool:
    """
    Check if remote_addr is in the allowlist CIDRs.

    Args:
        allowlist_raw: Allowlist config value (JSON array or free text),
            or None/empty to allow all
        remote_addr: Client IP address

    Returns:
        True if allowed, False if blocked
    """
    if not allowlist_raw:
        return True

    entries = _parse_ip_allowlist(allowlist_raw)
    if not entries:
        # Value was set but produced no usable entries — fail closed.
        logger.warning("IP allowlist configured but parsed to empty list")
        return False

    try:
        client_ip = ipaddress.ip_address(remote_addr)
        return any(
            client_ip in ipaddress.ip_network(entry, strict=False)
            for entry in entries
        )
    except ValueError as e:
        logger.warning(f"Invalid IP allowlist config: {e}")
        return False


def _validate_coordinates(locations: List[Dict]) -> str | None:
    """
    Validate coordinate bounds for all locations.

    Returns:
        Error message string if invalid, None if all valid
    """
    for loc in locations:
        lat = loc.get("lat")
        lon = loc.get("lon")
        # T5.4: NaN and +/-inf silently pass `<` and `>` comparisons
        # because they return False for both. Reject them explicitly
        # so bogus values never reach the CoT XML builder.
        if lat is not None:
            if not isinstance(lat, (int, float)) or not math.isfinite(lat):
                return f"Invalid coordinate: latitude {lat!r} is not a finite number"
            if lat < -90 or lat > 90:
                return f"Invalid coordinate: latitude {lat} outside ±90 range"
        if lon is not None:
            if not isinstance(lon, (int, float)) or not math.isfinite(lon):
                return f"Invalid coordinate: longitude {lon!r} is not a finite number"
            if lon < -180 or lon > 180:
                return f"Invalid coordinate: longitude {lon} outside ±180 range"
    return None


def _get_worker_for_stream(stream_id: int):
    """Look up the active InboundStreamWorker for a stream ID."""
    registry = get_active_inbound_streams()
    return registry.get(stream_id)


def _process_inbound_async(locations, stream) -> Dict:
    """
    Run the async InboundCOTService from a sync Flask context.

    Hypercorn dispatches sync views into a worker thread that has no
    event loop, so always create a fresh loop here.

    Returns:
        Result dict from InboundCOTService.process_inbound_locations
    """
    from services.inbound_cot_service import InboundCOTService

    service = InboundCOTService()
    return asyncio.run(
        service.process_inbound_locations(locations, stream)
    )


@bp.route("/<int:stream_id>/data", methods=["POST"])
def receive_inbound_data(stream_id: int):
    """Accept inbound tracker data pushed by an external source.

    Authenticates via a bearer token validated by the target
    stream's plugin (``plugin.validate_inbound_request``). Body
    format is plugin-specific (JSON, XML, form). Coordinates are
    validated before being enqueued for CoT dispatch.

    When the stream is in preview mode the request is buffered
    instead of dispatched, and a 202 with ``status: preview`` is
    returned so operators can inspect the mapped result before
    switching the stream to live mode.

    Anti-enumeration: any auth failure, missing stream, wrong
    stream mode, or blocked source IP returns the same 404
    response so external callers cannot probe for valid stream ids.
    ---
    tags: [Inbound]
    security:
      - bearerAuth: []
    parameters:
      - in: path
        name: stream_id
        required: true
        schema: {type: integer}
    requestBody:
      required: true
      description: >-
        Plugin-specific payload. JSON receiver plugins accept
        ``{"locations": [...]}``; XML/form receivers accept the
        wire format directly.
      content:
        application/json:
          schema: InboundPayloadSchema
        application/xml:
          schema:
            type: string
        application/x-www-form-urlencoded:
          schema:
            type: object
    responses:
      202:
        description: >-
          Payload accepted. ``status`` is ``accepted`` in live
          mode and ``preview`` when the stream is in preview mode.
        content:
          application/json:
            schema: InboundAckSchema
      400:
        description: >-
          Invalid payload, unparseable body, no locations
          extracted, coordinate validation failed, or the
          request exceeded the per-request location limit.
        content:
          application/json:
            schema: ErrorSchema
      404:
        description: >-
          Stream not found, inactive, wrong mode, source IP not
          in allowlist, or bearer token invalid.
          Anti-enumeration; do not treat as authoritative.
        content:
          application/json:
            schema: ErrorSchema
      413:
        description: Payload exceeded the maximum permitted size.
        content:
          application/json:
            schema: ErrorSchema
      415:
        description: >-
          Content-Type not accepted by the stream's plugin.
        content:
          application/json:
            schema: ErrorSchema
      429:
        description: Per-stream rate limit exceeded.
        content:
          application/json:
            schema: ErrorSchema
      500:
        description: Internal processing error during CoT dispatch.
        content:
          application/json:
            schema: ErrorSchema
    """
    # --- Payload size check (before any DB lookup) ---
    content_length = request.content_length or 0
    if content_length > MAX_PAYLOAD_BYTES:
        return jsonify({"error": "Payload too large"}), 413

    raw_body = request.get_data()
    if len(raw_body) > MAX_PAYLOAD_BYTES:
        return jsonify({"error": "Payload too large"}), 413

    # --- Stream lookup and validation ---
    stream = db.session.get(Stream, stream_id)

    if not stream or not stream.is_active or stream.stream_mode != "inbound":
        logger.debug(
            f"Inbound request rejected for stream {stream_id}: "
            + (
                "not found" if not stream
                else "inactive" if not stream.is_active
                else "wrong mode"
            )
        )
        return jsonify(_NOT_FOUND_RESPONSE[0]), _NOT_FOUND_RESPONSE[1]

    # --- Plugin instantiation (needed for config values and auth) ---
    plugin_manager = get_plugin_manager()
    plugin_class = plugin_manager.get_plugin_class(stream.plugin_type)
    if not plugin_class:
        logger.error(
            f"Plugin type '{stream.plugin_type}' not found "
            f"for stream {stream_id}"
        )
        return jsonify(_NOT_FOUND_RESPONSE[0]), _NOT_FOUND_RESPONSE[1]

    plugin = plugin_class(stream.get_plugin_config())
    plugin.stream = stream
    plugin_config = plugin.get_decrypted_config()

    # --- IP allowlist: plugin config preferred, stream column as fallback ---
    ip_allowlist = (
        plugin_config.get("ip_allowlist") or stream.inbound_ip_allowlist
    )
    if not _check_ip_allowlist(ip_allowlist, request.remote_addr):
        logger.warning(
            f"Inbound request blocked by IP allowlist "
            f"for stream {stream_id} from {request.remote_addr}"
        )
        return jsonify(_NOT_FOUND_RESPONSE[0]), _NOT_FOUND_RESPONSE[1]

    # --- Authentication ---
    headers = dict(request.headers)
    is_valid, auth_error = plugin.validate_inbound_request(headers)
    if not is_valid:
        auth_hdr = headers.get("Authorization", "")
        raw_key = auth_hdr[7:] if auth_hdr.startswith("Bearer ") else ""
        logger.warning(
            f"Inbound auth failed for stream {stream_id} "
            f"from {request.remote_addr} (key: {_mask_api_key(raw_key)})"
        )
        return jsonify(_NOT_FOUND_RESPONSE[0]), _NOT_FOUND_RESPONSE[1]

    # --- Rate limiting: plugin config preferred, stream column as fallback ---
    rate_limit = plugin_config.get("rate_limit") or stream.inbound_rate_limit
    if rate_limit is None:
        rate_limit = 60
    if _is_rate_limited(stream_id, int(rate_limit)):
        logger.warning(
            f"Inbound rate limit exceeded for stream {stream_id} "
            f"from {request.remote_addr} (limit: {rate_limit} req/min)"
        )
        return jsonify({"error": "Rate limit exceeded"}), 429

    # --- Content-Type validation ---
    content_type = request.content_type or ""
    # Strip parameters (e.g. "application/json; charset=utf-8")
    base_content_type = content_type.split(";")[0].strip().lower()
    accepted = [ct.lower() for ct in plugin.get_accepted_content_types()]
    if base_content_type not in accepted:
        return jsonify({
            "error": (
                f"Unsupported Content-Type: {content_type}. "
                f"Accepted: {', '.join(accepted)}"
            )
        }), 415

    # --- Payload transformation ---
    try:
        locations = plugin.transform_payload(raw_body, content_type, headers)
    except (ValueError, Exception) as e:
        logger.warning(
            f"Inbound transform failed for stream {stream_id}: {e}"
        )
        return jsonify({"error": "Payload transform failed"}), 400

    if not locations:
        return jsonify({"error": "No locations extracted from payload"}), 400

    # --- Location count limit ---
    if len(locations) > MAX_LOCATIONS_PER_REQUEST:
        return jsonify({
            "error": (
                f"Too many locations: {len(locations)} "
                f"(max {MAX_LOCATIONS_PER_REQUEST})"
            )
        }), 400

    # --- Coordinate validation ---
    coord_error = _validate_coordinates(locations)
    if coord_error:
        return jsonify({"error": coord_error}), 400

    # --- Preview mode: plugin config preferred, stream column as fallback ---
    preview_raw = plugin_config.get("preview_mode")
    if preview_raw is None:
        preview_mode = bool(stream.inbound_preview_mode)
    else:
        preview_mode = preview_raw in (True, "true", "True", "on", "1", 1)

    if preview_mode:
        worker = _get_worker_for_stream(stream_id)
        if worker:
            worker.capture_payload(
                raw_body=raw_body,
                content_type=content_type,
                headers=headers,
                source_ip=request.remote_addr,
                mapped_result=locations,
            )

        logger.info(
            f"Inbound preview: stream {stream_id} received "
            f"{len(locations)} locations from {request.remote_addr}"
        )

        return jsonify({
            "status": "preview",
            "locations_received": len(locations),
            "mapped_result": locations,
        }), 202

    # --- Process and distribute ---
    result = _process_inbound_async(locations, stream)

    if not result.get("success"):
        error_msg = result.get("error", "Internal processing error")
        logger.error(
            f"Inbound processing failed for stream "
            f"{stream_id}: {error_msg}"
        )
        stream.update_stats(error=error_msg)
        db.session.commit()
        return jsonify({"error": error_msg}), 500

    # --- Update stream stats ---
    events_created = result.get("events_created", 0)
    stream.update_stats(messages_sent=events_created)
    db.session.commit()

    logger.info(
        f"Inbound: stream {stream_id} received "
        f"{len(locations)} locations, "
        f"created {events_created} CoT events "
        f"from {request.remote_addr}"
    )

    return jsonify({
        "status": "accepted",
        "locations_received": len(locations),
        "events_created": events_created,
        "servers": result.get("servers", {}),
    }), 202


def _validate_inbound_stream(stream_id: int):
    """
    Look up a stream and verify it is an active inbound stream.

    Returns (stream, None) on success or (None, error_response) on failure.
    """
    stream = db.session.get(Stream, stream_id)
    if not stream or stream.stream_mode != "inbound":
        return None, (jsonify({"error": "Not found"}), 404)
    return stream, None


def _serialize_payload(entry: Dict) -> Dict:
    """
    Convert a capture buffer entry to JSON-safe format.

    raw_body (bytes) is decoded to UTF-8 if possible, otherwise
    represented as a base64 string.
    """
    raw = entry.get("raw_body", b"")
    try:
        raw_str = raw.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        import base64 as b64
        raw_str = b64.b64encode(raw).decode("ascii")

    return {
        "raw_body": raw_str,
        "content_type": entry.get("content_type", ""),
        "headers": entry.get("headers", {}),
        "source_ip": entry.get("source_ip", ""),
        "received_at": entry.get("received_at", ""),
        "mapped_result": entry.get("mapped_result", []),
    }


@bp.route("/<int:stream_id>/preview", methods=["GET"])
@api_key_or_auth_required
def get_preview(stream_id: int):
    """Return captured payloads for an inbound stream.

    When the stream is in preview mode, incoming requests are
    buffered instead of being dispatched to TAK. This endpoint
    returns those captured payloads (raw body, headers, source IP,
    and the mapped locations the plugin produced) so operators can
    verify the plugin's payload transform before switching to live
    mode.

    Requires a valid session or ``tb_pat_`` bearer token, and the
    stream must be an inbound stream.
    ---
    tags: [Inbound]
    parameters:
      - in: path
        name: stream_id
        required: true
        schema: {type: integer}
    responses:
      200:
        description: Captured payloads and current preview flag.
        content:
          application/json:
            schema: PreviewResponseSchema
      404:
        description: Stream not found or not an inbound stream.
        content:
          application/json:
            schema: ErrorSchema
    """
    stream, error = _validate_inbound_stream(stream_id)
    if error:
        return error

    worker = _get_worker_for_stream(stream_id)
    if not worker:
        return jsonify({
            "stream_id": stream_id,
            "preview_mode": stream.inbound_preview_mode,
            "payloads": [],
        }), 200

    payloads = worker.get_captured_payloads()

    return jsonify({
        "stream_id": stream_id,
        "preview_mode": stream.inbound_preview_mode,
        "payloads": [_serialize_payload(p) for p in payloads],
    }), 200


@bp.route("/<int:stream_id>/preview", methods=["DELETE"])
@api_key_or_auth_required
def clear_preview(stream_id: int):
    """Clear the capture buffer for an inbound stream.

    Discards every payload previously captured by preview mode.
    Idempotent — succeeds even when no payloads are buffered.
    Requires a valid session or ``tb_pat_`` bearer token.
    ---
    tags: [Inbound]
    parameters:
      - in: path
        name: stream_id
        required: true
        schema: {type: integer}
    responses:
      200:
        description: Buffer cleared.
        content:
          application/json:
            schema: PreviewClearedSchema
      404:
        description: Stream not found or not an inbound stream.
        content:
          application/json:
            schema: ErrorSchema
    """
    stream, error = _validate_inbound_stream(stream_id)
    if error:
        return error

    worker = _get_worker_for_stream(stream_id)
    if worker:
        worker.clear_captured_payloads()

    return jsonify({"status": "cleared"}), 200


@bp.route("/<int:stream_id>/preview/remap", methods=["POST"])
@api_key_or_auth_required
def remap_preview(stream_id: int):
    """Re-run payload transform with alternate plugin config.

    Applies an alternate plugin config over the stream's stored
    config and re-runs ``transform_payload`` on every currently-
    captured payload. Nothing is persisted — this is a "what would
    my mapping look like if I changed X" preview used by the
    stream edit UI.

    Returns one entry per captured payload with the received-at
    timestamp and either the mapped location list or an error
    object if the transform threw. Requires a valid session or
    ``tb_pat_`` bearer token.
    ---
    tags: [Inbound]
    parameters:
      - in: path
        name: stream_id
        required: true
        schema: {type: integer}
    requestBody:
      required: false
      content:
        application/json:
          schema: RemapRequestSchema
    responses:
      200:
        description: Remap results (one per captured payload).
        content:
          application/json:
            schema: RemapResponseSchema
      404:
        description: >-
          Stream not found, not an inbound stream, or plugin type
          no longer registered.
        content:
          application/json:
            schema: ErrorSchema
    """
    stream, error = _validate_inbound_stream(stream_id)
    if error:
        return error

    body = request.get_json(silent=True) or {}
    alt_config = body.get("plugin_config", {})

    worker = _get_worker_for_stream(stream_id)
    if not worker:
        return jsonify({"results": []}), 200

    captured = worker.get_captured_payloads()
    if not captured:
        return jsonify({"results": []}), 200

    # Instantiate plugin with the alternate config
    plugin_manager = get_plugin_manager()
    plugin_class = plugin_manager.get_plugin_class(stream.plugin_type)
    if not plugin_class:
        return jsonify({"error": "Plugin not found"}), 404

    # Merge stream's existing config with overrides
    base_config = stream.get_plugin_config() or {}
    merged_config = {**base_config, **alt_config}
    plugin = plugin_class(merged_config)
    plugin.stream = stream

    results = []
    for entry in captured:
        try:
            mapped = plugin.transform_payload(
                entry["raw_body"],
                entry["content_type"],
                entry["headers"],
            )
        except Exception as e:
            mapped = {"error": str(e)}

        results.append({
            "received_at": entry.get("received_at", ""),
            "mapped_result": mapped,
        })

    return jsonify({"results": results}), 200


@bp.route("/generate-api-key", methods=["POST"])
@require_permission("streams", "write")
def generate_api_key():
    """
    Generate a random API key for inbound stream authentication.

    Returns a cryptographically secure token that can be used as an
    inbound stream API key. Does not persist — the caller stores it
    in the stream creation/edit form.
    """
    import secrets as _secrets

    key = _secrets.token_urlsafe(32)
    return jsonify({"api_key": key}), 200
