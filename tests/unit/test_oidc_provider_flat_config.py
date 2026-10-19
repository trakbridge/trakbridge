"""
ABOUTME: Unit tests for OIDCAuthProvider accepting the flat schema from authentication.yaml
ABOUTME: Covers discovery URL derivation, scope joining, role_mapping alias, nested compatibility
"""

from unittest.mock import patch

import pytest

from services.auth.base_provider import ProviderConfigurationException
from services.auth.oidc_provider import OIDCAuthProvider

# A discovery document with every endpoint validate_configuration() requires.
# Patched in place of the network fetch so the real validation path runs.
DISCOVERY_DOCUMENT = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
    "jwks_uri": "https://idp.example.com/jwks",
}


def flat_oidc_config(**overrides):
    """
    Build the OIDC block exactly as authentication.yaml produces it.

    AuthenticationManager strips the 'enabled' key before handing the block to
    the provider, so it is deliberately absent here.
    """
    config = {
        "issuer": "https://idp.example.com",
        "client_id": "trakbridge-client",
        "client_secret": "super-secret",
        "scopes": ["openid", "email", "profile", "groups"],
        "redirect_uri": "https://trakbridge.example.com/auth/oidc/callback",
        "role_claim": "groups",
        "role_mapping": {
            "trakbridge-admins": "admin",
            "trakbridge-operators": "operator",
            "trakbridge-users": "user",
        },
        "default_role": "user",
    }
    config.update(overrides)
    return config


@pytest.fixture
def discovery():
    with patch.object(
        OIDCAuthProvider, "_get_discovery_document", return_value=DISCOVERY_DOCUMENT
    ):
        yield


class TestFlatConfigFromAuthenticationYaml:
    """The provider must accept the schema that config/settings/authentication.yaml emits"""

    def test_flat_config_constructs_provider(self, discovery):
        provider = OIDCAuthProvider(flat_oidc_config())

        assert provider.client_id == "trakbridge-client"
        assert provider.client_secret == "super-secret"
        assert provider.active_provider

    def test_flat_config_derives_discovery_url_from_issuer(self, discovery):
        provider = OIDCAuthProvider(flat_oidc_config())

        assert (
            provider.discovery_url
            == "https://idp.example.com/.well-known/openid-configuration"
        )

    def test_flat_config_derives_discovery_url_from_issuer_with_trailing_slash(
        self, discovery
    ):
        provider = OIDCAuthProvider(
            flat_oidc_config(issuer="https://idp.example.com/realms/tak/")
        )

        assert (
            provider.discovery_url
            == "https://idp.example.com/realms/tak/.well-known/openid-configuration"
        )

    def test_flat_config_explicit_discovery_url_overrides_issuer(self, discovery):
        provider = OIDCAuthProvider(
            flat_oidc_config(
                discovery_url="https://idp.example.com/custom/openid-configuration"
            )
        )

        assert (
            provider.discovery_url
            == "https://idp.example.com/custom/openid-configuration"
        )

    def test_flat_config_joins_scopes_list_into_scope_string(self, discovery):
        provider = OIDCAuthProvider(flat_oidc_config())

        assert provider.scope == "openid email profile groups"

    def test_flat_config_without_scopes_uses_default_scope(self, discovery):
        config = flat_oidc_config()
        del config["scopes"]

        provider = OIDCAuthProvider(config)

        assert provider.scope == "openid profile email"

    def test_flat_config_reads_role_mapping(self, discovery):
        provider = OIDCAuthProvider(flat_oidc_config())

        assert provider.role_mappings == {
            "trakbridge-admins": "admin",
            "trakbridge-operators": "operator",
            "trakbridge-users": "user",
        }

    def test_flat_config_without_client_id_fails_validation(self, discovery):
        with pytest.raises(ProviderConfigurationException) as exc_info:
            OIDCAuthProvider(flat_oidc_config(client_id=""))

        assert "Client ID is required" in str(exc_info.value.details["issues"])


class TestNestedConfigStillSupported:
    """The pre-existing multi-provider schema must keep working"""

    def test_nested_config_selects_enabled_provider(self, discovery):
        provider = OIDCAuthProvider(
            {
                "providers": {
                    "azure_ad": {
                        "enabled": True,
                        "client_id": "azure-client",
                        "client_secret": "azure-secret",
                        "discovery_url": (
                            "https://login.microsoftonline.com/tenant/v2.0"
                            "/.well-known/openid-configuration"
                        ),
                        "scope": "openid profile email",
                    }
                },
                "role_mappings": {"Admins": "admin"},
            }
        )

        assert provider.active_provider == "azure_ad"
        assert provider.client_id == "azure-client"
        assert provider.role_mappings == {"Admins": "admin"}

    def test_empty_config_raises_no_provider_enabled(self, discovery):
        with pytest.raises(ProviderConfigurationException, match="No OIDC provider"):
            OIDCAuthProvider({})

    def test_nested_config_with_all_providers_disabled_raises(self, discovery):
        with pytest.raises(ProviderConfigurationException, match="No OIDC provider"):
            OIDCAuthProvider(
                {"providers": {"azure_ad": {"enabled": False, "client_id": "x"}}}
            )
