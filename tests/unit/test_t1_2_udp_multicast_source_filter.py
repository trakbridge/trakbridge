# ABOUTME: Regression tests for T1.2 — UDP multicast listener must use
# ABOUTME: IGMPv3 SSM when source_filter is set, blocking spoofed CoT.
"""T1.2 — UDP multicast source filter blocks spoofed CoT injection.

The UDP multicast listener joins a multicast group. Without a source filter
any sender on the group can inject CoT. When source_filter is configured,
the plugin uses IP_ADD_SOURCE_MEMBERSHIP so the kernel only delivers datagrams
from listed sources — non-listed senders are dropped at the NIC before
userspace sees the packet.

Regression tests enforce:
1. source_filter config field exists and is optional.
2. Help text mentions SSM / source-specific multicast.
3. Empty source_filter → standard IP_ADD_MEMBERSHIP join.
4. Non-empty source_filter → one IP_ADD_SOURCE_MEMBERSHIP call per IP.
5. Whitespace around IPs is stripped.
6. Config validation rejects invalid IPs in source_filter.
7. Config validation rejects non-multicast multicast_group.
"""

import socket
import socket as _real_socket
from unittest.mock import MagicMock, patch

import pytest

from plugins.udp_multicast_listener import (
    UdpMulticastListener,
    _IP_ADD_SOURCE_MEMBERSHIP,
)

_GROUP = "239.2.3.1"
_PORT = 6969
_IFACE = "10.0.0.1"

_MIN_CONFIG = {
    "multicast_group": _GROUP,
    "multicast_port": _PORT,
    "bind_interface": _IFACE,
    "source_filter": "",
}


def _plugin(source_filter="", group=_GROUP, iface=_IFACE):
    return UdpMulticastListener(config={
        "multicast_group": group,
        "multicast_port": _PORT,
        "bind_interface": iface,
        "source_filter": source_filter,
    })


def _open_socket_mocked(plugin, source_filter="", group=_GROUP):
    """Call _open_socket with a mocked socket module; return setsockopt calls.
    """
    config = {
        "multicast_group": group,
        "multicast_port": _PORT,
        "bind_interface": _IFACE,
        "source_filter": source_filter,
    }
    mock_sock = MagicMock()
    with patch(
        "plugins.udp_multicast_listener.socket"
    ) as mock_socket_module:
        mock_socket_module.socket.return_value = mock_sock
        mock_socket_module.AF_INET = _real_socket.AF_INET
        mock_socket_module.SOCK_DGRAM = _real_socket.SOCK_DGRAM
        mock_socket_module.IPPROTO_UDP = _real_socket.IPPROTO_UDP
        mock_socket_module.SOL_SOCKET = _real_socket.SOL_SOCKET
        mock_socket_module.SO_REUSEADDR = _real_socket.SO_REUSEADDR
        mock_socket_module.SO_REUSEPORT = getattr(
            _real_socket, "SO_REUSEPORT", None
        )
        mock_socket_module.IPPROTO_IP = _real_socket.IPPROTO_IP
        mock_socket_module.IP_ADD_MEMBERSHIP = (
            _real_socket.IP_ADD_MEMBERSHIP
        )
        mock_socket_module.inet_aton = _real_socket.inet_aton
        plugin._open_socket(config)
    return mock_sock.setsockopt.call_args_list


class TestSourceFilterConfigField:
    """Config field exists, is optional, and documents SSM."""

    def test_field_exists_in_metadata(self):
        plugin = _plugin()
        fields = {
            f.name: f
            for f in plugin.plugin_metadata.get("config_fields", [])
        }
        assert "source_filter" in fields, (
            "UDP multicast plugin must have a 'source_filter' config field"
        )
        assert fields["source_filter"].field_type == "text"
        assert not fields["source_filter"].required

    def test_help_text_mentions_ssm(self):
        plugin = _plugin()
        fields = {
            f.name: f
            for f in plugin.plugin_metadata.get("config_fields", [])
        }
        help_text = (fields["source_filter"].help_text or "").lower()
        assert "ssm" in help_text or "source-specific" in help_text, (
            "source_filter help must mention SSM / source-specific multicast"
        )


class TestSocketJoinBehavior:
    """_open_socket() issues the correct IGMP join based on source_filter."""

    def test_no_ssm_join_when_source_filter_empty(self):
        """Empty source_filter → IP_ADD_MEMBERSHIP (standard multicast)."""
        calls = _open_socket_mocked(_plugin(), source_filter="")
        # setsockopt(level, optname, optval) → c[0] = (level, optname, optval)
        membership = [
            c for c in calls
            if c[0][0] == socket.IPPROTO_IP
            and c[0][1] == socket.IP_ADD_MEMBERSHIP
        ]
        ssm = [
            c for c in calls
            if c[0][0] == socket.IPPROTO_IP
            and c[0][1] == _IP_ADD_SOURCE_MEMBERSHIP
        ]
        assert len(membership) == 1, (
            "Empty source_filter must produce exactly one "
            "IP_ADD_MEMBERSHIP call"
        )
        assert len(ssm) == 0, (
            "Empty source_filter must not call IP_ADD_SOURCE_MEMBERSHIP"
        )

    def test_ssm_join_per_source_when_filter_set(self):
        """Two IPs in source_filter → two IP_ADD_SOURCE_MEMBERSHIP calls."""
        calls = _open_socket_mocked(
            _plugin(), source_filter="10.0.0.5, 10.0.0.6"
        )
        ssm = [
            c for c in calls
            if c[0][0] == socket.IPPROTO_IP
            and c[0][1] == _IP_ADD_SOURCE_MEMBERSHIP
        ]
        assert len(ssm) == 2, (
            "Two source IPs must produce two "
            "IP_ADD_SOURCE_MEMBERSHIP calls"
        )

    def test_whitespace_stripped_from_source_filter(self):
        """Whitespace around IPs is stripped before building mreq."""
        calls = _open_socket_mocked(
            _plugin(), source_filter="  10.0.0.5  ,  10.0.0.6  "
        )
        ssm = [
            c for c in calls
            if c[0][0] == socket.IPPROTO_IP
            and c[0][1] == _IP_ADD_SOURCE_MEMBERSHIP
        ]
        assert len(ssm) == 2, (
            "Whitespace in source_filter must be stripped; "
            "expected two SSM joins"
        )

    def test_single_source_produces_one_ssm_join(self):
        """Single IP in source_filter → exactly one SSM join."""
        calls = _open_socket_mocked(
            _plugin(), source_filter="10.0.0.5"
        )
        ssm = [
            c for c in calls
            if c[0][0] == socket.IPPROTO_IP
            and c[0][1] == _IP_ADD_SOURCE_MEMBERSHIP
        ]
        assert len(ssm) == 1


class TestConfigValidation:
    """validate_config() catches bad IPs before _open_socket() is called.

    Invalid configs raise ValueError with an operator-readable message so
    update_stream_safely()/create_stream() can surface the reason in the
    UI — matches the T1.3 pattern. Returning False alone got swallowed
    by the save-time hook, letting invalid configs persist.
    """

    def test_invalid_ip_in_source_filter_rejected(self):
        plugin = UdpMulticastListener(config={
            **_MIN_CONFIG,
            "source_filter": "10.0.0.5, not-an-ip",
        })
        with pytest.raises(ValueError, match=r"not-an-ip"):
            plugin.validate_config()

    def test_cidr_in_source_filter_rejected(self):
        """SSM requires exact IPs; CIDRs are not valid mreq source addrs."""
        plugin = UdpMulticastListener(config={
            **_MIN_CONFIG,
            "source_filter": "10.0.0.0/24",
        })
        with pytest.raises(ValueError, match=r"10\.0\.0\.0/24"):
            plugin.validate_config()

    def test_valid_source_filter_passes_validation(self):
        plugin = UdpMulticastListener(config={
            **_MIN_CONFIG,
            "source_filter": "10.0.0.5, 10.0.0.6",
        })
        assert plugin.validate_config() is True

    def test_empty_source_filter_passes_validation(self):
        plugin = UdpMulticastListener(config={**_MIN_CONFIG})
        assert plugin.validate_config() is True

    def test_non_multicast_group_rejected(self):
        plugin = UdpMulticastListener(config={
            **_MIN_CONFIG,
            "multicast_group": "10.0.0.1",
        })
        with pytest.raises(ValueError, match=r"not a multicast address"):
            plugin.validate_config()

    def test_invalid_group_address_rejected(self):
        plugin = UdpMulticastListener(config={
            **_MIN_CONFIG,
            "multicast_group": "not-an-ip",
        })
        with pytest.raises(ValueError, match=r"not a valid IP"):
            plugin.validate_config()


class TestSaveTimeValidationRejectsInvalidUdpConfig:
    """Regression: both create_stream() and update_stream_safely() must
    surface UDP validator errors to the UI, not silently persist the
    invalid config. Reported live — the initial fix only wired the
    probe into update_stream_safely(); create_stream() had no probe
    at all, so freshly-created streams saved invalid configs and the
    error only appeared when the listener tried to start.
    """

    def test_create_stream_rejects_invalid_multicast_group(
        self, app, db_session
    ):
        from unittest.mock import MagicMock
        from models.tak_server import TakServer
        from services.stream_operations_service import StreamOperationsService

        with app.app_context():
            server = TakServer(
                name="udp-s1", host="h1", port=8089, protocol="ssl"
            )
            db_session.add(server)
            db_session.commit()

            stream_mgr = MagicMock()
            stream_mgr.refresh_stream_tak_workers.return_value = True
            svc = StreamOperationsService(stream_mgr, db_session)

            result = svc.create_stream({
                "name": "Bad UDP Group",
                "plugin_type": "udp_multicast_listener",
                "tak_servers": [str(server.id)],
                "plugin_multicast_group": "10.0.0.1",  # unicast, not multicast
                "plugin_multicast_port": "6969",
                "plugin_bind_interface": "0.0.0.0",
            })

            assert result["success"] is False, (
                "create_stream must refuse a non-multicast multicast_group; "
                f"got {result}"
            )
            assert "multicast" in result["error"].lower(), (
                f"Error message must mention 'multicast'; got {result['error']}"
            )

    def test_create_stream_rejects_invalid_source_filter(
        self, app, db_session
    ):
        from unittest.mock import MagicMock
        from models.tak_server import TakServer
        from services.stream_operations_service import StreamOperationsService

        with app.app_context():
            server = TakServer(
                name="udp-s2", host="h1", port=8089, protocol="ssl"
            )
            db_session.add(server)
            db_session.commit()

            stream_mgr = MagicMock()
            stream_mgr.refresh_stream_tak_workers.return_value = True
            svc = StreamOperationsService(stream_mgr, db_session)

            result = svc.create_stream({
                "name": "Bad UDP Filter",
                "plugin_type": "udp_multicast_listener",
                "tak_servers": [str(server.id)],
                "plugin_multicast_group": "239.2.3.1",
                "plugin_multicast_port": "6969",
                "plugin_bind_interface": "0.0.0.0",
                "plugin_source_filter": "10.0.0.5, not-an-ip",
            })

            assert result["success"] is False, (
                "create_stream must refuse a source_filter with an invalid "
                f"IP; got {result}"
            )
            assert "not-an-ip" in result["error"], (
                f"Error must name the bad entry; got {result['error']}"
            )
