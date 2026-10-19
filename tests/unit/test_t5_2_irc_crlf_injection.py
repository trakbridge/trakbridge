# ABOUTME: Regression tests for T5.2 — IRC handler must strip CR/LF from
# ABOUTME: message payloads to prevent protocol injection via CoT field values.
"""T5.2 — IRC CRLF injection prevention.

IRC uses `\\r\\n` as a command separator. Untrusted CoT-derived
values (callsign, remarks, group name, etc.) flow into the message
template unchanged; a value containing `\\r\\nJOIN #evil` would let
an attacker inject arbitrary IRC commands with the bot's privileges.

The fix sanitises message and channel at the socket-write chokepoint
in `_send_to_irc()`. CR/LF are replaced with a single space, NUL bytes
are dropped.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plugins.irc_handler import IRCHandler


class TestSanitiseHelper:
    """The static helper strips every CR/LF/NUL variant."""

    @pytest.mark.parametrize("payload,expected", [
        ("alice", "alice"),
        ("alice\r\nJOIN #evil", "alice JOIN #evil"),
        ("alice\rJOIN #evil", "alice JOIN #evil"),
        ("alice\nJOIN #evil", "alice JOIN #evil"),
        ("alice\r\n\r\nQUIT", "alice  QUIT"),
        ("alice\x00hidden", "alicehidden"),
        # CR/LF -> single space (each). NUL -> dropped (not replaced).
        ("multi\r\nline\rmessage\nwith\x00nulls",
         "multi line message withnulls"),
        ("", ""),
    ])
    def test_sanitises_control_chars(self, payload, expected):
        assert IRCHandler._sanitize_irc_payload(payload) == expected

    def test_none_or_empty_returns_input(self):
        assert IRCHandler._sanitize_irc_payload("") == ""
        assert IRCHandler._sanitize_irc_payload(None) is None


class TestSendToIRCSanitises:
    """`_send_to_irc()` writes only sanitised bytes to the socket."""

    def _make_handler(self, channel="#trakbridge"):
        handler = IRCHandler(config={})
        handler._connected = True
        writer = MagicMock()
        writer.is_closing.return_value = False
        writer.drain = AsyncMock()
        handler._writer = writer
        handler._reader = MagicMock()
        return handler, writer, channel

    @pytest.mark.asyncio
    async def test_crlf_in_message_stripped_before_write(self):
        handler, writer, channel = self._make_handler()
        with patch.object(
            handler, "get_decrypted_config", return_value={"channel": channel}
        ):
            await handler._send_to_irc(
                "alice\r\nJOIN #evil\r\nPRIVMSG #evil :owned"
            )

        # Collect every byte string handed to writer.write()
        written = b"".join(
            call.args[0] for call in writer.write.call_args_list
        )
        # After sanitisation, only ONE PRIVMSG line — the CoT-derived
        # CR/LF sequences must have been squashed to spaces.
        assert written.count(b"\r\n") == 1, (
            "CR/LF in the message body was not sanitised; the wire "
            f"contains multiple protocol separators: {written!r}"
        )
        assert b"JOIN #evil" in written, (
            "Sanity: the literal string still appears (squashed to "
            "harmless text), just not as a protocol command"
        )

    @pytest.mark.asyncio
    async def test_crlf_in_channel_stripped_before_write(self):
        """Defence in depth: channel comes from config, but a compromised
        config file or a future admin-UI edit shouldn't be able to
        inject commands via the channel name."""
        handler, writer, _ = self._make_handler(
            channel="#trakbridge\r\nJOIN #evil"
        )
        with patch.object(
            handler,
            "get_decrypted_config",
            return_value={"channel": "#trakbridge\r\nJOIN #evil"},
        ):
            await handler._send_to_irc("hello")

        written = b"".join(
            call.args[0] for call in writer.write.call_args_list
        )
        assert written.count(b"\r\n") == 1, (
            "CR/LF in the channel name was not sanitised"
        )

    @pytest.mark.asyncio
    async def test_clean_message_passes_through(self):
        """Regression guard: normal messages still deliver unchanged."""
        handler, writer, channel = self._make_handler()
        with patch.object(
            handler, "get_decrypted_config", return_value={"channel": channel}
        ):
            await handler._send_to_irc("alice is at MGRS 33UWP...")

        written = b"".join(
            call.args[0] for call in writer.write.call_args_list
        )
        assert b"PRIVMSG #trakbridge :alice is at MGRS 33UWP...\r\n" in written

    @pytest.mark.asyncio
    async def test_null_byte_dropped(self):
        handler, writer, channel = self._make_handler()
        with patch.object(
            handler, "get_decrypted_config", return_value={"channel": channel}
        ):
            await handler._send_to_irc("alice\x00hidden")

        written = b"".join(
            call.args[0] for call in writer.write.call_args_list
        )
        assert b"\x00" not in written
        assert b"alicehidden" in written
