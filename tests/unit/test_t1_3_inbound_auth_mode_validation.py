# ABOUTME: Regression tests for T1.3 — generic inbound plugins with
# ABOUTME: auth_mode=none must require a non-empty ip_allowlist.
"""T1.3 — auth_mode=none requires ip_allowlist.

Generic inbound plugins (JSON and XML) support auth_mode=none for testing.
Without any authentication, the endpoints are world-accessible. The fix
requires an explicit ip_allowlist when auth_mode=none is set.

Regression tests enforce:
1. Both plugins declare an ip_allowlist config field in metadata.
2. validate_config() rejects auth_mode=none with empty ip_allowlist.
3. validate_config() accepts auth_mode=none with explicit 0.0.0.0/0.
4. validate_config() accepts newline- and comma-separated CIDR lists.
5. validate_config() rejects invalid IPs / CIDRs in the allowlist.
6. validate_config() does not require ip_allowlist when auth_mode=api_key.
7. _check_ip_allowlist() at request time still honours the JSON legacy
   format and the new text format.
"""

import pytest

from plugins.generic_inbound_plugin import GenericInboundPlugin
from plugins.generic_xml_inbound_plugin import GenericXMLInboundPlugin
from routes.inbound import _check_ip_allowlist, _parse_ip_allowlist


_JSON_MIN = {
    "lat_field": "lat",
    "lon_field": "lon",
    "uid_field": "id",
    "callsign_field": "name",
}
_XML_MIN = {
    "items_xpath": "//device",
    "lat_xpath": "lat",
    "lon_xpath": "lon",
    "uid_xpath": "id",
    "callsign_xpath": "name",
}


def _mk(cls, overrides):
    base = _JSON_MIN if cls is GenericInboundPlugin else _XML_MIN
    return cls(config={**base, **overrides})


class TestIPAllowlistConfigField:
    """Both generic plugins expose an ip_allowlist textarea field."""

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_field_exists(self, cls):
        plugin = _mk(cls, {})
        fields = {
            f.name: f
            for f in plugin.plugin_metadata.get("config_fields", [])
        }
        assert "ip_allowlist" in fields, (
            f"{cls.__name__} must declare an 'ip_allowlist' config field"
        )
        assert fields["ip_allowlist"].field_type == "textarea"
        assert not fields["ip_allowlist"].required, (
            "ip_allowlist is conditionally required (via validate_config), "
            "not statically required — otherwise all api_key configs break."
        )


class TestValidateConfigEnforcement:
    """validate_config() raises ValueError when the invariant is broken."""

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_auth_mode_none_with_empty_allowlist_raises(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "none",
            "ip_allowlist": "",
        })
        with pytest.raises(ValueError, match=r"Allowlist|allowlist"):
            plugin.validate_config()

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_auth_mode_none_with_wildcard_accepted(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "none",
            "ip_allowlist": "0.0.0.0/0",
        })
        assert plugin.validate_config() is True

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_auth_mode_none_with_cidr_list_accepted(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "none",
            "ip_allowlist": "10.0.0.0/8\n192.168.1.42",
        })
        assert plugin.validate_config() is True

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_comma_separated_allowlist_accepted(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "none",
            "ip_allowlist": "10.0.0.5, 10.0.0.6, 192.168.0.0/16",
        })
        assert plugin.validate_config() is True

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_invalid_ip_in_allowlist_raises(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "none",
            "ip_allowlist": "10.0.0.5\nnot-an-ip",
        })
        with pytest.raises(ValueError, match=r"not a valid"):
            plugin.validate_config()

    @pytest.mark.parametrize("cls", [
        GenericInboundPlugin,
        GenericXMLInboundPlugin,
    ])
    def test_auth_mode_api_key_does_not_require_allowlist(self, cls):
        plugin = _mk(cls, {
            "auth_mode": "api_key",
            "api_key": "secret123",
            "ip_allowlist": "",
        })
        assert plugin.validate_config() is True


class TestParseIpAllowlist:
    """_parse_ip_allowlist() accepts JSON legacy and new text formats."""

    def test_json_array_legacy_format(self):
        assert _parse_ip_allowlist(
            '["10.0.0.0/8", "192.168.1.1"]'
        ) == ["10.0.0.0/8", "192.168.1.1"]

    def test_newline_separated(self):
        assert _parse_ip_allowlist(
            "10.0.0.0/8\n192.168.1.1"
        ) == ["10.0.0.0/8", "192.168.1.1"]

    def test_comma_separated(self):
        assert _parse_ip_allowlist(
            "10.0.0.0/8, 192.168.1.1"
        ) == ["10.0.0.0/8", "192.168.1.1"]

    def test_mixed_separators_and_whitespace(self):
        assert _parse_ip_allowlist(
            "  10.0.0.0/8  ,\n  192.168.1.1  \n\n"
        ) == ["10.0.0.0/8", "192.168.1.1"]

    def test_empty_returns_empty(self):
        assert _parse_ip_allowlist("") == []
        assert _parse_ip_allowlist(None) == []


class TestCheckIpAllowlistRuntime:
    """_check_ip_allowlist() enforces the allowlist at request time."""

    def test_empty_allowlist_allows_all(self):
        assert _check_ip_allowlist("", "10.0.0.5") is True
        assert _check_ip_allowlist(None, "10.0.0.5") is True

    def test_wildcard_matches_any(self):
        assert _check_ip_allowlist("0.0.0.0/0", "8.8.8.8") is True
        assert _check_ip_allowlist("0.0.0.0/0", "192.168.1.1") is True

    def test_ip_in_cidr_range_allowed(self):
        assert _check_ip_allowlist("10.0.0.0/8", "10.5.5.5") is True

    def test_ip_outside_cidr_range_blocked(self):
        assert _check_ip_allowlist("10.0.0.0/8", "192.168.1.1") is False

    def test_exact_ip_match_allowed(self):
        assert _check_ip_allowlist("192.168.1.42", "192.168.1.42") is True

    def test_exact_ip_no_match_blocked(self):
        assert _check_ip_allowlist("192.168.1.42", "192.168.1.43") is False

    def test_legacy_json_format_still_works(self):
        """Existing streams stored allowlist as JSON — must keep working."""
        assert _check_ip_allowlist(
            '["10.0.0.0/8"]', "10.5.5.5"
        ) is True
        assert _check_ip_allowlist(
            '["10.0.0.0/8"]', "192.168.1.1"
        ) is False

    def test_new_text_format_multiple_entries(self):
        allowlist = "10.0.0.0/8\n192.168.1.42"
        assert _check_ip_allowlist(allowlist, "10.5.5.5") is True
        assert _check_ip_allowlist(allowlist, "192.168.1.42") is True
        assert _check_ip_allowlist(allowlist, "172.16.0.1") is False

    def test_malformed_config_fails_closed(self):
        """Junk config value → deny (not allow)."""
        assert _check_ip_allowlist(
            "definitely not an ip", "10.0.0.5"
        ) is False


class TestSaveTimeValidationRejectsInvalidAuthMode:
    """Regression: create_stream() must probe validate_config() too.

    Reported live — the initial 2.2.1 fix only wired the probe into
    update_stream_safely(). A freshly-created stream with
    auth_mode=none and no ip_allowlist saved silently, and the error
    only surfaced when the listener tried to start.
    """

    def test_create_stream_rejects_auth_mode_none_without_allowlist(
        self, app, db_session
    ):
        from unittest.mock import MagicMock
        from models.tak_server import TakServer
        from services.stream_operations_service import StreamOperationsService

        with app.app_context():
            server = TakServer(
                name="json-s1", host="h1", port=8089, protocol="ssl"
            )
            db_session.add(server)
            db_session.commit()

            stream_mgr = MagicMock()
            stream_mgr.refresh_stream_tak_workers.return_value = True
            svc = StreamOperationsService(stream_mgr, db_session)

            result = svc.create_stream({
                "name": "Bad JSON Auth",
                "plugin_type": "generic_json_inbound",
                "tak_servers": [str(server.id)],
                "plugin_auth_mode": "none",
                "plugin_ip_allowlist": "",  # missing — must be rejected
                "plugin_lat_field": "lat",
                "plugin_lon_field": "lon",
                "plugin_uid_field": "id",
                "plugin_callsign_field": "name",
            })

            assert result["success"] is False, (
                "create_stream must refuse auth_mode=none with empty "
                f"ip_allowlist; got {result}"
            )
            assert "allowlist" in result["error"].lower(), (
                f"Error must mention allowlist; got {result['error']}"
            )

    def test_create_stream_rejects_invalid_ip_in_allowlist(
        self, app, db_session
    ):
        from unittest.mock import MagicMock
        from models.tak_server import TakServer
        from services.stream_operations_service import StreamOperationsService

        with app.app_context():
            server = TakServer(
                name="json-s2", host="h1", port=8089, protocol="ssl"
            )
            db_session.add(server)
            db_session.commit()

            stream_mgr = MagicMock()
            stream_mgr.refresh_stream_tak_workers.return_value = True
            svc = StreamOperationsService(stream_mgr, db_session)

            result = svc.create_stream({
                "name": "Bad JSON IP",
                "plugin_type": "generic_json_inbound",
                "tak_servers": [str(server.id)],
                "plugin_auth_mode": "none",
                "plugin_ip_allowlist": "10.0.0.5, not-an-ip",
                "plugin_lat_field": "lat",
                "plugin_lon_field": "lon",
                "plugin_uid_field": "id",
                "plugin_callsign_field": "name",
            })

            assert result["success"] is False
            assert "not-an-ip" in result["error"], (
                f"Error must name the bad entry; got {result['error']}"
            )
