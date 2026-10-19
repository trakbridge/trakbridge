"""
ABOUTME: End-to-end test of the OIDC login redirect using the flat authentication.yaml schema
ABOUTME: Serves a real HTTP discovery document and asserts POST /auth/login redirects to the IdP
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from services.auth.auth_manager import AuthenticationManager
from tests.conftest import get_csrf_token


class DiscoveryHandler(BaseHTTPRequestHandler):
    """Serves an OpenID Connect discovery document from a local HTTP server"""

    def do_GET(self):
        base = f"http://{self.headers['Host']}"
        if self.path == "/.well-known/openid-configuration":
            document = {
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "userinfo_endpoint": f"{base}/userinfo",
                "jwks_uri": f"{base}/jwks",
            }
        elif self.path == "/jwks":
            document = {"keys": []}
        else:
            self.send_response(404)
            self.end_headers()
            return

        body = json.dumps(document).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        # Keep test output pristine
        pass


@pytest.fixture
def identity_provider():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def oidc_enabled_app(app, identity_provider):
    """Swap the app's auth manager for one built from the flat OIDC schema"""
    auth_config = {
        "session": {"lifetime_hours": 8, "cleanup_interval_minutes": 60},
        "provider_priority": ["oidc", "local"],
        "providers": {
            "local": {"enabled": True},
            "oidc": {
                "enabled": True,
                "issuer": identity_provider,
                "client_id": "trakbridge-e2e",
                "client_secret": "e2e-secret",
                "scopes": ["openid", "email", "profile"],
                "role_mapping": {"trakbridge-admins": "admin"},
                "default_role": "user",
            },
        },
    }
    original_manager = getattr(app, "auth_manager", None)
    with app.app_context():
        app.auth_manager = AuthenticationManager(auth_config)
    try:
        yield app
    finally:
        app.auth_manager = original_manager


@pytest.mark.e2e
@pytest.mark.oidc
class TestOIDCLoginRedirect:
    def test_login_redirects_browser_to_identity_provider(
        self, oidc_enabled_app, identity_provider
    ):
        client = oidc_enabled_app.test_client()
        client.get("/auth/login")
        token = get_csrf_token(client, oidc_enabled_app)

        response = client.post(
            "/auth/login",
            data={"auth_method": "oidc", "csrf_token": token},
        )

        assert response.status_code == 302
        location = urlparse(response.headers["Location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            f"{identity_provider}/authorize"
        )

        query = parse_qs(location.query)
        assert query["client_id"] == ["trakbridge-e2e"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["openid email profile"]
        assert query["redirect_uri"] == [
            f"{oidc_enabled_app.config['APPLICATION_URL']}/auth/oidc/callback"
        ]

        with client.session_transaction() as flask_session:
            assert flask_session["oidc_state"] == query["state"][0]
