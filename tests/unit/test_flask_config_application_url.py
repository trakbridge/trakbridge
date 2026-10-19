"""
ABOUTME: Unit test that the app factory exposes APPLICATION_URL in Flask config
ABOUTME: The OIDC login route builds its callback redirect URI from this key
"""

from config import get_config


def test_application_url_is_copied_into_flask_config(app):
    config_instance = get_config("testing")

    assert app.config["APPLICATION_URL"] == config_instance.APPLICATION_URL
    assert app.config["APPLICATION_URL"].startswith("http")
