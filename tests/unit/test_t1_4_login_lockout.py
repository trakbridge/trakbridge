# ABOUTME: Regression tests for T1.4 — failed-login counter, account
# ABOUTME: lockout, and the admin unlock action for local users.
"""T1.4 — Login lockout and admin unlock.

The failed-login counter, is_locked() check, lock_account(),
unlock_account(), and per-provider integration for local users all
already exist. This test file covers:

1. Counter increments on failed local login and resets on success.
2. Account locks after max_login_attempts consecutive failures.
3. Locked account is refused login even with the correct password.
4. Admin dedicated /unlock endpoint clears the lockout without
   mutating status. Non-admin cannot hit it.
5. The Unlock button renders on the admin user detail page only when
   the user is both locked and not disabled.
6. Fix regression: config/schema.py used a stale 15-min default
   in seconds; runtime uses 30 min. The dataclass field name and
   validation bounds now agree with the runtime consumer.
"""

from datetime import datetime, timedelta, timezone

import pytest

from database import db
from models.user import AccountStatus, AuthProvider, User, UserRole
from services.auth.local_provider import LocalAuthProvider
from tests.conftest import get_csrf_token


LOCAL_CONFIG = {
    "enabled": True,
    "password_policy": {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": False,
    },
}


def _create_lockout_user(username="lockout_target"):
    """Create + commit a local user; return its id.

    Callers re-fetch the user via User.query.get(uid) inside their own
    app_context so nothing gets detached across contexts.
    """
    user = User(
        username=username,
        email=f"{username}@test.com",
        full_name="Lockout Target",
        role=UserRole.USER,
        auth_provider=AuthProvider.LOCAL,
    )
    user.set_password("CorrectPass123")
    db.session.add(user)
    db.session.commit()
    return user.id


class TestFailedLoginCounter:
    """Counter increments on failed local login and resets on success."""

    def test_failed_login_increments_counter(self, app, db_session):
        with app.app_context():
            uid = _create_lockout_user("counter_inc")
            provider = LocalAuthProvider(LOCAL_CONFIG)

            provider.authenticate("counter_inc", "wrongpass")

            refreshed = User.query.get(uid)
            assert refreshed.failed_login_attempts == 1

    def test_successful_login_resets_counter(self, app, db_session):
        with app.app_context():
            uid = _create_lockout_user("counter_reset")
            u = User.query.get(uid)
            u.failed_login_attempts = 3
            db.session.commit()

            provider = LocalAuthProvider(LOCAL_CONFIG)
            response = provider.authenticate(
                "counter_reset", "CorrectPass123"
            )
            assert response.success is True

            refreshed = User.query.get(uid)
            assert refreshed.failed_login_attempts == 0


class TestAccountLockout:
    """Account locks after N failures, refuses even the correct password."""

    def test_lock_triggers_after_threshold(self, app, db_session):
        with app.app_context():
            uid = _create_lockout_user("lock_threshold")
            provider = LocalAuthProvider(LOCAL_CONFIG)
            threshold = 5  # matches default in auth_manager

            for _ in range(threshold):
                provider.authenticate("lock_threshold", "wrongpass")

            refreshed = User.query.get(uid)
            assert refreshed.is_locked(), (
                f"Account should be locked after {threshold} failures; "
                f"failed_attempts={refreshed.failed_login_attempts}, "
                f"locked_until={refreshed.locked_until}"
            )

    def test_locked_account_refuses_correct_password(
        self, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("locked_refuse")
            u = User.query.get(uid)
            u.lock_account(duration_minutes=30)
            db.session.commit()

            provider = LocalAuthProvider(LOCAL_CONFIG)
            response = provider.authenticate(
                "locked_refuse", "CorrectPass123"
            )
            assert response.success is False, (
                "Correct password on a locked account must still be "
                "refused. Existing behaviour — regression guard."
            )

    def test_expired_locked_until_reports_not_locked(self, app, db_session):
        """locked_until in the past AND status==ACTIVE → is_locked False.

        `is_locked()` returns True if EITHER the status is LOCKED or the
        locked_until timestamp is in the future. So to prove the
        timestamp-only path we must leave status as ACTIVE.
        """
        with app.app_context():
            uid = _create_lockout_user("expired_lock")
            u = User.query.get(uid)
            u.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            u.status = AccountStatus.ACTIVE  # only the timestamp gates
            db.session.commit()

            refreshed = User.query.get(uid)
            assert not refreshed.is_locked(), (
                "locked_until in the past on an ACTIVE account must "
                "report is_locked=False"
            )


class TestAdminUnlockEndpoint:
    """POST /auth/admin/users/<id>/unlock clears the lock without status change."""

    def test_admin_can_unlock_locked_user(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("admin_unlock")
            u = User.query.get(uid)
            u.lock_account(duration_minutes=30)
            db.session.commit()

        client = authenticated_client("admin")
        csrf = get_csrf_token(client, app)

        resp = client.post(
            f"/auth/admin/users/{uid}/unlock",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303), (
            f"Expected redirect after unlock, got {resp.status_code}"
        )

        with app.app_context():
            refreshed = User.query.get(uid)
            assert refreshed.locked_until is None
            assert refreshed.failed_login_attempts == 0
            # Status returns to ACTIVE (not left as LOCKED)
            assert refreshed.status == AccountStatus.ACTIVE

    def test_unlock_endpoint_noop_when_user_not_locked(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("not_locked")

        client = authenticated_client("admin")
        csrf = get_csrf_token(client, app)

        resp = client.post(
            f"/auth/admin/users/{uid}/unlock",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        # Redirect back with an info flash — endpoint accepts the request
        assert resp.status_code in (302, 303)

    def test_non_admin_cannot_unlock(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("non_admin_target")
            u = User.query.get(uid)
            u.lock_account(duration_minutes=30)
            db.session.commit()

        client = authenticated_client("user")
        csrf = get_csrf_token(client, app)

        resp = client.post(
            f"/auth/admin/users/{uid}/unlock",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        # 302 to login/deny, or 401/403 depending on the decorator chain
        assert resp.status_code in (302, 303, 401, 403), (
            f"Non-admin must be denied; got {resp.status_code}"
        )

        with app.app_context():
            refreshed = User.query.get(uid)
            assert refreshed.is_locked(), (
                "Lockout must remain in place after a non-admin attempt"
            )

    def test_unlock_requires_csrf(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("csrf_target")
            u = User.query.get(uid)
            u.lock_account(duration_minutes=30)
            db.session.commit()

        client = authenticated_client("admin")

        # No csrf_token in body
        resp = client.post(f"/auth/admin/users/{uid}/unlock", data={})
        assert resp.status_code in (400, 403), (
            f"Missing CSRF must be rejected; got {resp.status_code}"
        )


class TestUnlockButtonTemplate:
    """The Unlock button appears only for locked-and-active users."""

    def test_button_rendered_for_locked_active_user(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("locked_active")
            u = User.query.get(uid)
            u.lock_account(duration_minutes=30)
            # lock_account() flips status to LOCKED. To simulate the
            # "locked-but-active" state (which is what our button
            # gates on), keep status ACTIVE but preserve locked_until.
            u.status = AccountStatus.ACTIVE
            db.session.commit()

        client = authenticated_client("admin")
        resp = client.get(f"/auth/admin/users/{uid}")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "Unlock User" in body, (
            "Locked user detail page must render the Unlock button"
        )
        assert f"/auth/admin/users/{uid}/unlock" in body

    def test_button_not_rendered_for_unlocked_user(
        self, authenticated_client, app, db_session
    ):
        with app.app_context():
            uid = _create_lockout_user("not_locked_view")

        client = authenticated_client("admin")
        resp = client.get(f"/auth/admin/users/{uid}")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "Unlock User" not in body, (
            "Unlock button must not render when the user is not locked"
        )


class TestSchemaAlignsWithRuntime:
    """Regression: config/schema.py once had a stale 15-min default in
    seconds while auth_manager used 30 min. Both must agree now."""

    def test_security_config_uses_minutes_field(self):
        from config.schema import SecurityConfig

        cfg = SecurityConfig()
        assert hasattr(cfg, "lockout_duration_minutes"), (
            "SecurityConfig dataclass must expose lockout_duration_minutes "
            "(the runtime consumes minutes, not seconds)."
        )
        assert not hasattr(cfg, "lockout_duration"), (
            "Legacy `lockout_duration` seconds field must be removed to "
            "prevent operators reading a stale default."
        )
        assert cfg.lockout_duration_minutes == 30, (
            "Default lockout duration must be 30 minutes to match "
            "services/auth/auth_manager.py:73-101 runtime default."
        )

    def test_max_login_attempts_default(self):
        from config.schema import SecurityConfig

        cfg = SecurityConfig()
        assert cfg.max_login_attempts == 5

    def test_json_schema_uses_minutes_field(self):
        from config.schema import CONFIG_SCHEMAS

        security = CONFIG_SCHEMAS.get("security", {})
        assert "lockout_duration_minutes" in security, (
            "JSON schema key must be lockout_duration_minutes to match "
            "the dataclass and runtime"
        )
        assert "lockout_duration" not in security
