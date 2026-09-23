# ABOUTME: Regression tests for the HTTPException error handler — ensures 429
# ABOUTME: (and other HTTP-status errors) are not swallowed into a 500.
"""HTTPException handler regression.

Prior to this fix the catch-all `@app.errorhandler(Exception)` handler
swallowed HTTPExceptions from Flask-Limiter and rendered them as 500
"This page isn't working" errors — hiding the real rate-limit reason
from the user.

The new `@app.errorhandler(HTTPException)` short-circuits those:

- 429 gets a friendly `errors/429.html` template (browser) or a JSON
  `{error, description}` payload (API client)
- Rate-limit hits emit a WARNING naming the source IP and endpoint
- Non-HTTPException exceptions continue to hit the generic 500 handler
"""

from werkzeug.exceptions import Forbidden, TooManyRequests


class TestHTTPExceptionHandlerDirect:
    """Drive the handler directly via test_request_context — no route setup
    required, works around Flask 3's post-first-request routing lock."""

    def _get_handler(self, app):
        """Look up our HTTPException handler by walking the registry."""
        from werkzeug.exceptions import HTTPException

        # Flask stores handlers keyed by (blueprint_or_None, exception_class)
        registry = app.error_handler_spec.get(None, {})
        for code_or_none, exception_map in registry.items():
            for exc_class, handler in exception_map.items():
                if exc_class is HTTPException:
                    return handler
        raise AssertionError(
            "No @app.errorhandler(HTTPException) handler registered — the "
            "catch-all Exception handler will swallow HTTP status codes."
        )

    def test_handler_is_registered(self, app):
        # If this fails, the fix has been reverted or never landed.
        self._get_handler(app)

    def test_429_html_returns_template(self, app):
        handler = self._get_handler(app)
        with app.test_request_context("/some/path"):
            resp = handler(TooManyRequests("test rate limit hit"))
            # handler returns (body, status) tuple for HTML path
            if isinstance(resp, tuple):
                body, status = resp
                assert status == 429
                assert "429" in body
                assert "Too Many Requests" in body
            else:
                # Fallback (no template) — Werkzeug Response
                assert resp.status_code == 429

    def test_429_json_returns_json_payload(self, app):
        handler = self._get_handler(app)
        with app.test_request_context(
            "/some/path", headers={"Accept": "application/json"}
        ):
            resp = handler(TooManyRequests("test rate limit hit"))
            # jsonify path returns (Response, status) tuple
            if isinstance(resp, tuple):
                response, status = resp
                assert status == 429
                payload = response.get_json()
            else:
                assert resp.status_code == 429
                payload = resp.get_json()
            assert "error" in payload
            assert "description" in payload

    def test_403_preserved(self, app):
        handler = self._get_handler(app)
        with app.test_request_context("/some/path"):
            resp = handler(Forbidden("test forbidden"))
            if isinstance(resp, tuple):
                _, status = resp
                assert status == 403
            else:
                assert resp.status_code == 403

    def test_429_logs_warning(self, app, caplog):
        handler = self._get_handler(app)
        with app.test_request_context("/some/path"):
            with caplog.at_level("WARNING"):
                handler(TooManyRequests("test rate limit hit"))
        rate_hits = [
            r for r in caplog.records
            if "Rate limit exceeded" in r.message
        ]
        assert rate_hits, (
            "429 hits must produce a WARNING for operator visibility"
        )

    def test_403_does_not_log_rate_limit_message(self, app, caplog):
        """Only 429 gets the rate-limit WARNING — 403 shouldn't."""
        handler = self._get_handler(app)
        with app.test_request_context("/some/path"):
            with caplog.at_level("WARNING"):
                handler(Forbidden("test forbidden"))
        rate_hits = [
            r for r in caplog.records
            if "Rate limit exceeded" in r.message
        ]
        assert not rate_hits, (
            "Non-429 HTTP exceptions must not produce the rate-limit "
            "WARNING (log noise)"
        )


class Test429TemplateExists:
    """The 429.html template must exist and follow the base_error pattern."""

    def test_template_file_present(self):
        from pathlib import Path
        assert Path("templates/errors/429.html").exists(), (
            "templates/errors/429.html must exist — the HTTPException "
            "handler renders it for browser callers"
        )

    def test_template_extends_base_error(self):
        from pathlib import Path
        content = Path("templates/errors/429.html").read_text()
        assert 'extends "errors/base_error.html"' in content, (
            "429 template must extend errors/base_error.html for "
            "consistent styling with 404 and 500 pages"
        )
