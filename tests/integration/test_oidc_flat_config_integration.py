"""
ABOUTME: Integration tests for AuthenticationManager registering OIDC from the flat YAML schema
ABOUTME: Exercises the real manager-to-provider wiring with the shape authentication.yaml produces
"""

from unittest.mock import patch

import pytest

from models.user import AuthProvider
from services.auth.auth_manager import AuthenticationManager
from services.auth.oidc_provider import OIDCAuthProvider

DISCOVERY_DOCUMENT = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
    "jwks_uri": "https://idp.example.com/jwks",
}


def yaml_shaped_auth_config(oidc_enabled: bool) -> dict:
    """Mirror the structure config/settings/authentication.yaml resolves to"""
    return {
        "session": {"lifetime_hours": 8, "cleanup_interval_minutes": 60},
        "provider_priority": ["oidc", "ldap", "local"],
        "providers": {
            "local": {"enabled": True},
            "ldap": {"enabled": False},
            "oidc": {
                "enabled": oidc_enabled,
                "issuer": "https://idp.example.com",
                "client_id": "trakbridge-client",
                "client_secret": "super-secret",
                "scopes": ["openid", "email", "profile", "groups"],
                "redirect_uri": "https://trakbridge.example.com/auth/oidc/callback",
                "role_claim": "groups",
                "role_mapping": {"trakbridge-admins": "admin"},
                "default_role": "user",
            },
        },
    }


@pytest.mark.integration
class TestAuthenticationManagerRegistersFlatOIDC:
    def test_enabled_flat_oidc_block_registers_provider(self, app):
        with (
            app.app_context(),
            patch.object(
                OIDCAuthProvider,
                "_get_discovery_document",
                return_value=DISCOVERY_DOCUMENT,
            ),
        ):
            manager = AuthenticationManager(yaml_shaped_auth_config(oidc_enabled=True))

        assert AuthProvider.OIDC in manager.providers
        provider = manager.providers[AuthProvider.OIDC]
        assert provider.client_id == "trakbridge-client"
        assert (
            provider.discovery_url
            == "https://idp.example.com/.well-known/openid-configuration"
        )
        assert provider.role_mappings == {"trakbridge-admins": "admin"}

    def test_disabled_flat_oidc_block_is_skipped(self, app):
        with app.app_context():
            manager = AuthenticationManager(yaml_shaped_auth_config(oidc_enabled=False))

        assert AuthProvider.OIDC not in manager.providers
        assert AuthProvider.LOCAL in manager.providers
