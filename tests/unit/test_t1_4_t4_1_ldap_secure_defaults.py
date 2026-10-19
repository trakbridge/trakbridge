# ABOUTME: Regression tests for T4.1 — LDAP must refuse plaintext bind and
# ABOUTME: negotiate StartTLS on port 389 before sending credentials.
"""T4.1 — LDAP secure-by-default.

Prior behaviour: `use_tls: true` in config was a no-op. The
`Connection(..., auto_bind=False)` call meant `start_tls()` was never
issued, so bind and every user password went to port 389 in cleartext.
`validate_cert: true` provided false assurance because no TLS handshake
ever happened.

Fix wired here:

- `_create_connection()` calls `connection.start_tls()` when
  `use_tls=true` and `use_ssl=false`. LDAPS (`use_ssl=true`) is
  already TLS at socket dial time and needs no upgrade.
- `validate_configuration()` refuses configs where neither
  `use_ssl` nor `use_tls` is set (plaintext) unless the operator
  opts in with `allow_insecure=true`.
- Same validator refuses `validate_cert=false` when TLS is on unless
  `allow_insecure=true`.
- When `allow_insecure=true`, startup emits a WARNING per-server so
  the insecure choice is visible in every log.

The tests below drive the real LDAPAuthProvider (with the ldap3
Connection swapped out for a mock) — no stubs.
"""

from unittest.mock import MagicMock, patch

import pytest

from services.auth.base_provider import (
    ProviderConfigurationException,
    ProviderConnectionException,
)
from services.auth.ldap_provider import LDAPAuthProvider


def _base_config(**overrides):
    """Minimum viable LDAP config; overrides substitute test-specific bits."""
    cfg = {
        "enabled": True,
        "server": "ldap://ldap.example.com",
        "port": 389,
        "use_ssl": False,
        "use_tls": True,  # secure default
        "validate_cert": True,
        "bind_dn": "CN=svc,DC=example,DC=com",
        "bind_password": "svc-pw",
        "user_search_base": "OU=Users,DC=example,DC=com",
        "user_search_filter": "(sAMAccountName={username})",
    }
    cfg.update(overrides)
    return cfg


# =========================================================================
# Config validator
# =========================================================================


class TestValidatorRejectsInsecureDefaults:
    """Plaintext or unverified TLS must be an explicit opt-in."""

    def test_plaintext_389_without_opt_in_rejected(self):
        with pytest.raises(ProviderConfigurationException) as exc_info:
            LDAPAuthProvider(
                _base_config(use_ssl=False, use_tls=False, port=389)
            )
        issues = exc_info.value.details.get("issues", [])
        combined = " ".join(issues).lower()
        assert (
            "plaintext" in combined
            or "ldaps" in combined
            or "starttls" in combined
        ), f"Reason should mention TLS/LDAPS; got issues={issues}"

    def test_plaintext_389_with_allow_insecure_accepted(self):
        # Must not raise
        LDAPAuthProvider(
            _base_config(
                use_ssl=False,
                use_tls=False,
                port=389,
                allow_insecure=True,
            )
        )

    def test_tls_true_validate_cert_false_rejected(self):
        with pytest.raises(ProviderConfigurationException):
            LDAPAuthProvider(
                _base_config(use_tls=True, validate_cert=False)
            )

    def test_tls_true_validate_cert_false_with_allow_insecure_accepted(self):
        LDAPAuthProvider(
            _base_config(
                use_tls=True,
                validate_cert=False,
                allow_insecure=True,
            )
        )

    def test_starttls_default_accepted(self):
        """use_tls=true, port 389, validate_cert=true — the ship default."""
        LDAPAuthProvider(_base_config())

    def test_ldaps_default_accepted(self):
        """LDAPS on 636 with cert validation is also acceptable."""
        LDAPAuthProvider(
            _base_config(
                server="ldaps://ldap.example.com",
                use_ssl=True,
                use_tls=False,
                port=636,
                validate_cert=True,
            )
        )


# =========================================================================
# Startup WARNING for insecure opt-in
# =========================================================================


class TestInsecureOptInLogsWarning:
    """When allow_insecure=true the operator sees a WARNING every start."""

    def test_plaintext_opt_in_emits_warning(self, caplog):
        with caplog.at_level("WARNING", logger="services.auth.ldap_provider"):
            LDAPAuthProvider(
                _base_config(
                    use_ssl=False,
                    use_tls=False,
                    port=389,
                    allow_insecure=True,
                )
            )
        assert any(
            "allow_insecure" in rec.message
            and "plaintext" in rec.message
            and "ldap.example.com" in rec.message
            for rec in caplog.records
        ), (
            "Insecure LDAP startup must log a WARNING naming the "
            f"server and the specific insecure option. Got: "
            f"{[r.message for r in caplog.records]}"
        )

    def test_tls_without_cert_validation_opt_in_emits_warning(self, caplog):
        with caplog.at_level("WARNING", logger="services.auth.ldap_provider"):
            LDAPAuthProvider(
                _base_config(
                    use_tls=True,
                    validate_cert=False,
                    allow_insecure=True,
                )
            )
        assert any(
            "cert validation disabled" in rec.message
            for rec in caplog.records
        ), (
            "validate_cert=false opt-in must WARN about disabled cert "
            "validation"
        )

    def test_secure_config_does_not_warn(self, caplog):
        with caplog.at_level("WARNING", logger="services.auth.ldap_provider"):
            LDAPAuthProvider(_base_config())
        # Shipping-default config should not produce an allow_insecure
        # warning
        assert not any(
            "allow_insecure" in rec.message for rec in caplog.records
        )


# =========================================================================
# _create_connection() actually calls start_tls()
# =========================================================================


class TestStartTLSNegotiatedBeforeBind:
    """StartTLS runs before any bind attempt on plaintext port 389."""

    def _mock_conn(self):
        conn = MagicMock()
        conn.start_tls.return_value = True
        conn.bind.return_value = True
        return conn

    def test_use_tls_calls_start_tls(self):
        provider = LDAPAuthProvider(_base_config())  # use_tls=True
        mock_conn = self._mock_conn()
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            provider._get_connection()

        mock_conn.start_tls.assert_called_once()

    def test_use_ssl_does_not_call_start_tls(self):
        provider = LDAPAuthProvider(
            _base_config(
                server="ldaps://ldap.example.com",
                use_ssl=True,
                use_tls=False,
                port=636,
                validate_cert=True,
            )
        )
        mock_conn = self._mock_conn()
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            provider._get_connection()

        mock_conn.start_tls.assert_not_called()

    def test_plaintext_opt_in_does_not_call_start_tls(self):
        """allow_insecure lets plaintext through — no StartTLS attempted."""
        provider = LDAPAuthProvider(
            _base_config(
                use_ssl=False,
                use_tls=False,
                port=389,
                allow_insecure=True,
            )
        )
        mock_conn = self._mock_conn()
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            provider._get_connection()

        mock_conn.start_tls.assert_not_called()

    def test_start_tls_failure_raises_and_prevents_bind(self):
        provider = LDAPAuthProvider(_base_config())
        mock_conn = self._mock_conn()
        mock_conn.start_tls.return_value = False
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            with pytest.raises(ProviderConnectionException) as exc_info:
                provider._get_connection()

        assert "starttls" in str(exc_info.value).lower()
        # Critically: no bind attempted after failed upgrade
        mock_conn.bind.assert_not_called()

    def test_anonymous_connection_still_upgrades_tls(self):
        """Anonymous bind path (no bind_dn) also gets StartTLS."""
        cfg = _base_config()
        cfg["bind_dn"] = ""
        cfg["bind_password"] = ""
        provider = LDAPAuthProvider(cfg)
        mock_conn = self._mock_conn()
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            provider._get_connection()

        mock_conn.start_tls.assert_called_once()

    def test_user_auth_connection_upgrades_before_password_sent(self):
        """User-cred connection: StartTLS must be called BEFORE bind."""
        provider = LDAPAuthProvider(_base_config())
        mock_conn = self._mock_conn()
        with patch(
            "services.auth.ldap_provider.Connection",
            return_value=mock_conn,
        ):
            provider._get_connection(
                user_dn="CN=alice,OU=Users,DC=example,DC=com",
                password="user-pw",
            )

        # Both are called; enforce ordering
        assert mock_conn.start_tls.called
        # bind not called yet — Connection() with auto_bind=False and
        # our start_tls happens before the caller triggers .bind()
        mock_conn.bind.assert_not_called()
