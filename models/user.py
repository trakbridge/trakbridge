"""
ABOUTME: User model for authentication system supporting multiple auth providers
ABOUTME: Tracks users from OIDC, LDAP, and local authentication with roles and sessions

File: models/user.py

Description:
    User authentication model supporting multiple authentication providers (OIDC, LDAP, Local).
    Implements role-based access control, session management, and user profile management.
    Provides secure password hashing for local authentication and tracks provider-specific
    user identifiers for external authentication systems.

Key features:
    - Multi-provider authentication support (OIDC, LDAP, Local)
    - Role-based access control with predefined roles
    - Secure password hashing using bcrypt for local authentication
    - User session tracking and management
    - Provider-specific user ID tracking for external auth
    - Account status management (active, disabled, locked)
    - Audit trail with creation and update timestamps
    - User profile information (name, email, preferences)

Author: Emfour Solutions
Created: 2025-07-26
"""

import uuid

# Standard library imports
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# Third-party imports
import bcrypt
from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

# Local application imports
from database import TimestampMixin, db


class AuthProvider(Enum):
    """Authentication provider types"""

    LOCAL = "local"
    OIDC = "oidc"
    LDAP = "ldap"


class UserRole(Enum):
    """User role definitions for RBAC"""

    ADMIN = "admin"  # Full system access
    OPERATOR = "operator"  # Stream and server management
    VIEWER = "viewer"  # Read-only access
    USER = "user"  # Basic authenticated access


class AccountStatus(Enum):
    """User account status"""

    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"
    PENDING = "pending"


class User(db.Model, TimestampMixin):
    """
    User model supporting multi-provider authentication
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    # Core user information
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    full_name = Column(String(255), nullable=True)

    # Authentication provider information
    auth_provider = Column(
        SQLEnum(AuthProvider), nullable=False, default=AuthProvider.LOCAL, index=True
    )
    provider_user_id = Column(
        String(255), nullable=True, index=True
    )  # External provider user ID
    provider_metadata = Column(Text, nullable=True)  # JSON metadata from provider

    # Local authentication (only used for LOCAL provider)
    password_hash = Column(String(255), nullable=True)

    # Authorization and status
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.USER)
    status = Column(
        SQLEnum(AccountStatus), nullable=False, default=AccountStatus.ACTIVE, index=True
    )

    # Security and session management
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, nullable=True)
    must_change_password = Column(Boolean, nullable=False, default=False)

    # User preferences
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")

    # Relationships
    sessions = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    api_keys = relationship(
        "UserApiKey", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.username} ({self.auth_provider.value})>"

    def set_password(self, password: str) -> None:
        """
        Set password hash for local authentication

        Args:
            password: Plain text password to hash
        """
        if self.auth_provider != AuthProvider.LOCAL:
            raise ValueError("Password can only be set for local authentication users")

        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
            "utf-8"
        )
        self.password_changed_at = datetime.now(timezone.utc)

    def check_password(self, password: str) -> bool:
        """
        Check password for local authentication

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches, False otherwise
        """
        if self.auth_provider != AuthProvider.LOCAL or not self.password_hash:
            return False

        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def _lockout_expired(self) -> bool:
        """True when `locked_until` is set and has already passed."""
        if not self.locked_until:
            return False
        current_time = datetime.now(timezone.utc)
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            # Naive timestamps from the DB are assumed to be UTC.
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return locked_until <= current_time

    def _auto_unlock_if_expired(self) -> bool:
        """Lazy auto-unlock: if the lockout window has passed, clear it
        and flip status back to ACTIVE. Returns True when an unlock
        actually happened so the caller can commit.

        Called from `is_active()` and `is_locked()` so the very next
        login attempt after the window expires sees a clean account,
        without needing a background scheduler.
        """
        if not self._lockout_expired():
            return False
        self.locked_until = None
        self.failed_login_attempts = 0
        if self.status == AccountStatus.LOCKED:
            self.status = AccountStatus.ACTIVE
        return True

    def _persist_auto_unlock(self) -> None:
        """Commit a lazy auto-unlock, best-effort.

        Called from `is_active()` / `is_locked()` after the mutation.
        Kept private and best-effort because these accessors get called
        in many contexts (templates, log lines) where a failed commit
        should not raise. The next successful commit will pick up the
        change anyway; this just persists it eagerly.
        """
        try:
            from database import db
            db.session.commit()
        except Exception:
            try:
                from database import db
                db.session.rollback()
            except Exception:
                pass

    def is_active(self) -> bool:
        """Check if user account is active"""
        # Lazy auto-unlock: an expired lockout should not keep the
        # account inactive. Runs before the status check because a
        # LOCKED account whose window has passed becomes ACTIVE here.
        if self._auto_unlock_if_expired():
            self._persist_auto_unlock()

        if self.status != AccountStatus.ACTIVE:
            return False

        return True

    def is_locked(self) -> bool:
        """Check if user account is locked"""
        # Lazy auto-unlock: if the lockout window has passed, drop the
        # LOCKED status so subsequent checks report the account as free.
        if self._auto_unlock_if_expired():
            self._persist_auto_unlock()
            return False

        if self.status == AccountStatus.LOCKED:
            return True

        if self.locked_until:
            current_time = datetime.now(timezone.utc)
            locked_until = self.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            return locked_until > current_time

        return False

    def lock_account(self, duration_minutes: int = 30) -> None:
        """
        Temporarily lock user account

        Args:
            duration_minutes: How long to lock the account in minutes
        """
        self.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=duration_minutes
        )
        self.status = AccountStatus.LOCKED

    def unlock_account(self) -> None:
        """Unlock user account"""
        self.locked_until = None
        self.failed_login_attempts = 0
        if self.status == AccountStatus.LOCKED:
            self.status = AccountStatus.ACTIVE

    def increment_failed_login(self, max_attempts: int = 5) -> None:
        """
        Increment failed login attempts and lock if necessary

        Args:
            max_attempts: Maximum allowed failed attempts before locking
        """
        self.failed_login_attempts += 1

        if self.failed_login_attempts >= max_attempts:
            self.lock_account()

    def reset_failed_login(self) -> None:
        """Reset failed login attempts after successful login"""
        self.failed_login_attempts = 0
        self.last_login = datetime.now(timezone.utc)

    def has_role(self, role: UserRole) -> bool:
        """
        Check if user has specific role

        Args:
            role: Role to check

        Returns:
            True if user has the role or higher privileges
        """
        role_hierarchy = {
            UserRole.VIEWER: 0,
            UserRole.USER: 1,
            UserRole.OPERATOR: 2,
            UserRole.ADMIN: 3,
        }

        user_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(role, 0)

        return user_level >= required_level

    def can_access(self, resource: str, action: str = "read") -> bool:
        """
        Check if user can access a specific resource with given action

        Args:
            resource: Resource name (e.g., 'streams', 'admin', 'tak_servers')
            action: Action type ('read', 'write', 'delete', 'admin')

        Returns:
            True if user has access, False otherwise
        """
        # Admin has access to everything
        if self.role == UserRole.ADMIN:
            return True

        # Define access control matrix
        permissions = {
            UserRole.VIEWER: {
                "streams": ["read"],
                "tak_servers": ["read"],
                "dashboard": ["read"],
                "api": ["read"],
            },
            UserRole.USER: {
                "streams": ["read"],
                "tak_servers": ["read"],
                "dashboard": ["read"],
                "api": ["read"],
                "profile": ["read", "write"],
                # api_keys: self-service management of the user's own
                # keys. Ownership is enforced at the route layer;
                # this grant is scoped to acting on rows owned by
                # request.user.
                "api_keys": ["read", "write", "delete"],
            },
            UserRole.OPERATOR: {
                "streams": ["read", "write", "delete"],
                "tak_servers": ["read", "write", "delete"],
                "dashboard": ["read"],
                "api": ["read", "write"],
                "profile": ["read", "write"],
                "api_keys": ["read", "write", "delete"],
            },
        }

        user_permissions = permissions.get(self.role, {})
        resource_permissions = user_permissions.get(resource, [])

        return action in resource_permissions

    def update_from_provider(self, provider_data: Dict[str, Any]) -> None:
        """
        Update user information from external provider data

        Args:
            provider_data: User data from authentication provider
        """
        # Update basic info if provided
        if "email" in provider_data and provider_data["email"]:
            self.email = provider_data["email"]

        if "full_name" in provider_data and provider_data["full_name"]:
            self.full_name = provider_data["full_name"]

        if "name" in provider_data and provider_data["name"]:
            self.full_name = provider_data["name"]

        # Update provider metadata
        import json

        # Create a serializable copy of provider_data
        serializable_data = {}
        for key, value in provider_data.items():
            if isinstance(value, UserRole):
                # Convert UserRole enum to string
                serializable_data[key] = value.value
            elif hasattr(value, "__dict__"):
                # Skip complex objects that can't be serialized
                serializable_data[key] = str(value)
            else:
                serializable_data[key] = value

        self.provider_metadata = json.dumps(serializable_data)

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert user to dictionary representation

        Args:
            include_sensitive: Whether to include sensitive information

        Returns:
            Dictionary representation of user
        """
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "auth_provider": self.auth_provider.value,
            "role": self.role.value,
            "status": self.status.value,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "timezone": self.timezone,
            "language": self.language,
            "is_active": self.is_active(),
            "is_locked": self.is_locked(),
        }

        if include_sensitive:
            data.update(
                {
                    "provider_user_id": self.provider_user_id,
                    "failed_login_attempts": self.failed_login_attempts,
                    "locked_until": (
                        self.locked_until.isoformat() if self.locked_until else None
                    ),
                    "password_changed_at": (
                        self.password_changed_at.isoformat()
                        if self.password_changed_at
                        else None
                    ),
                }
            )

        return data

    @classmethod
    def create_local_user(
        cls,
        username: str,
        password: str,
        email: str = None,
        full_name: str = None,
        role: UserRole = UserRole.USER,
    ) -> "User":
        """
        Create a new local authentication user

        Args:
            username: Unique username
            password: Plain text password
            email: User email address
            full_name: User's full name
            role: User role

        Returns:
            New User instance
        """
        user = cls(
            username=username,
            email=email,
            full_name=full_name,
            auth_provider=AuthProvider.LOCAL,
            role=role,
            status=AccountStatus.ACTIVE,
        )
        user.set_password(password)

        return user

    @classmethod
    def create_external_user(
        cls,
        username: str,
        provider: AuthProvider,
        provider_user_id: str,
        provider_data: Dict[str, Any] = None,
        role: UserRole = UserRole.USER,
    ) -> "User":
        """
        Create a new external authentication user (OIDC/LDAP)

        Args:
            username: Unique username
            provider: Authentication provider
            provider_user_id: User ID from external provider
            provider_data: Additional data from provider
            role: User role

        Returns:
            New User instance
        """
        user = cls(
            username=username,
            auth_provider=provider,
            provider_user_id=provider_user_id,
            role=role,
            status=AccountStatus.ACTIVE,
        )

        if provider_data:
            user.update_from_provider(provider_data)

        return user


class UserSession(db.Model, TimestampMixin):
    """
    User session model for tracking active sessions
    """

    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Session information
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    provider = Column(SQLEnum(AuthProvider), nullable=False, default=AuthProvider.LOCAL)

    # Session lifecycle
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_activity = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_active = Column(Boolean, default=True, index=True)

    # Provider-specific session data
    provider_session_data = Column(Text, nullable=True)  # JSON data from provider

    # Relationships
    user = relationship("User", back_populates="sessions")

    def __repr__(self):
        return f"<UserSession {self.session_id} for {self.user.username}>"

    @classmethod
    def create_session(
        cls,
        user: User,
        provider: AuthProvider = AuthProvider.LOCAL,
        expires_in_hours: int = 24,
        ip_address: str = None,
        user_agent: str = None,
        provider_session_data: Dict[str, Any] = None,
    ) -> "UserSession":
        """
        Create a new user session

        Args:
            user: User to create session for
            provider: Authentication provider used for this session
            expires_in_hours: Session duration in hours
            ip_address: Client IP address
            user_agent: Client user agent string
            provider_session_data: Provider-specific session data

        Returns:
            New UserSession instance
        """
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        session = cls(
            session_id=session_id,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            provider=provider,
            expires_at=expires_at,
            last_activity=datetime.now(timezone.utc),
            is_active=True,
        )

        if provider_session_data:
            import json

            session.provider_session_data = json.dumps(provider_session_data)

        return session

    def is_valid(self) -> bool:
        """Check if session is still valid"""
        # Ensure both datetimes are timezone-aware for comparison
        current_time = datetime.now(timezone.utc)

        # Handle case where expires_at might be naive (for backwards compatibility)
        if self.expires_at.tzinfo is None:
            # If expires_at is naive, assume it's UTC and make it timezone-aware
            expires_at = self.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at = self.expires_at

        return self.is_active and expires_at > current_time and self.user.is_active()

    def extend_session(self, hours: int = 24) -> None:
        """
        Extend session expiration time

        Args:
            hours: Number of hours to extend session
        """
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
        self.last_activity = datetime.now(timezone.utc)

    def invalidate(self) -> None:
        """Invalidate the session"""
        self.is_active = False

    def update_activity(self) -> bool:
        """
        Update last activity timestamp with 5-minute throttling

        Returns:
            bool: True if activity was updated (DB commit needed), False if skipped
        """
        from datetime import timedelta

        current_time = datetime.now(timezone.utc)

        # Only update if more than 5 minutes have passed since last update
        if not self.last_activity:
            # No previous activity, update immediately
            self.last_activity = current_time
            return True

        # Handle timezone-aware comparison (ensure both datetimes have timezone info)
        last_activity = self.last_activity
        if last_activity.tzinfo is None:
            # If last_activity is naive, assume it's UTC and make it timezone-aware
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        # Check if more than 5 minutes have passed
        if (current_time - last_activity) > timedelta(minutes=5):
            self.last_activity = current_time
            return True  # Signal that DB commit is needed

        return False  # Skip DB update - not enough time has passed

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary representation"""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "provider": self.provider.value,
            "expires_at": self.expires_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_active": self.is_active,
            "is_valid": self.is_valid(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# Constants used by both the model and services/auth/api_key_service.
# Kept here so the model file is the single source of truth for the
# on-the-wire token shape.
API_KEY_TOKEN_PREFIX = "tb_pat_"
API_KEY_PREVIEW_CHARS = 12
# `tb_pat_` (7) + 12-char preview = 19 stored in token_prefix column.
API_KEY_PREFIX_LEN = len(API_KEY_TOKEN_PREFIX) + API_KEY_PREVIEW_CHARS
API_KEY_TOKEN_ENTROPY_BYTES = 32  # 256 bits — secrets.token_urlsafe(32)
API_KEY_SALT_BYTES = 16


class UserApiKey(db.Model, TimestampMixin):
    """Per-user API key for programmatic access to the JSON API.

    Storage model: the plaintext token (``tb_pat_<44 base64url>``) is
    shown to the user once at creation and never stored. What we
    persist is ``token_prefix`` (first 19 chars, for UI display and
    fast lookup) and ``token_hash`` (HMAC-SHA256 of ``salt + token``
    using a process-wide pepper from ``API_KEY_PEPPER``). A per-key
    random salt prevents rainbow-table attacks against the pepper;
    the pepper prevents a DB-only leak from being sufficient to
    verify tokens offline.

    Bcrypt is intentionally NOT used here. Bcrypt is designed for
    low-entropy user passwords; API tokens are 256-bit random values
    where HMAC-SHA256 (industry standard, e.g. GitHub, Stripe) is
    both safe and much faster on the request path.
    """

    __tablename__ = "user_api_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(100), nullable=False)
    token_prefix = Column(String(19), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    token_salt = Column(String(32), nullable=False)
    scopes = Column(Text, nullable=False, default="[]")
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)

    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<UserApiKey {self.token_prefix}... user_id={self.user_id}>"

    # ------------------------------------------------------------------
    # Crypto helpers (module-level statics kept on the model so the
    # model file is a single source of truth for token shape/hashing).
    # ------------------------------------------------------------------

    @staticmethod
    def _pepper() -> bytes:
        """Import lazily so the module can be imported before
        services.auth.pepper.load_pepper() has run at app startup.
        """
        from services.auth.pepper import get_pepper

        return get_pepper()

    @staticmethod
    def hash_token(salt: str, token: str) -> str:
        """Deterministic HMAC-SHA256 of the token using per-key salt
        and the process-wide pepper. Returns lowercase hex.
        """
        import hashlib
        import hmac

        return hmac.new(
            UserApiKey._pepper(),
            (salt + token).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def generate_plaintext() -> str:
        """Generate a fresh plaintext token with the standard prefix."""
        import secrets

        return API_KEY_TOKEN_PREFIX + secrets.token_urlsafe(
            API_KEY_TOKEN_ENTROPY_BYTES
        )

    @staticmethod
    def new_salt() -> str:
        """Generate a random per-key salt (32 hex chars = 16 bytes)."""
        import secrets

        return secrets.token_hex(API_KEY_SALT_BYTES)

    # ------------------------------------------------------------------
    # Factory + instance methods
    # ------------------------------------------------------------------

    @classmethod
    def generate(
        cls,
        user: "User",
        name: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
    ) -> "tuple[UserApiKey, str]":
        """Create and persist a new key. Returns (row, plaintext_token).

        The plaintext token is returned to the caller so it can be
        shown to the user exactly once; the DB never sees it.
        """
        import json

        plaintext = cls.generate_plaintext()
        salt = cls.new_salt()
        instance = cls(
            user=user,
            name=name,
            token_prefix=plaintext[:API_KEY_PREFIX_LEN],
            token_hash=cls.hash_token(salt, plaintext),
            token_salt=salt,
            scopes=json.dumps(list(scopes)),
            expires_at=expires_at,
            is_active=True,
        )
        db.session.add(instance)
        db.session.commit()
        return instance, plaintext

    def verify(self, plaintext: str) -> bool:
        """Constant-time verification of a candidate plaintext token."""
        import hmac

        expected = self.hash_token(self.token_salt, plaintext)
        return hmac.compare_digest(expected, self.token_hash)

    def is_valid(self) -> bool:
        """True when the key is usable right now.

        Checks: not revoked, active flag, expiry not passed, owning
        user is still ACTIVE. Any single failure returns False.
        """
        if self.revoked_at is not None:
            return False
        if not self.is_active:
            return False
        if self.expires_at is not None:
            now = datetime.now(timezone.utc)
            # Normalise naive DB values to UTC to survive SQLite's
            # tz-stripping (mirrors UserSession.is_valid pattern).
            expires = self.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now >= expires:
                return False
        if self.user is None or not self.user.is_active():
            return False
        return True

    def revoke(self) -> None:
        """Mark this key as revoked. Idempotent."""
        if self.revoked_at is None:
            self.revoked_at = datetime.now(timezone.utc)
        self.is_active = False

    def scope_list(self) -> List[str]:
        """Parse the stored JSON scopes into a list of strings."""
        import json

        try:
            parsed = json.loads(self.scopes or "[]")
        except (ValueError, TypeError):
            return []
        return [s for s in parsed if isinstance(s, str)]

    def scope_groups(self) -> List[Dict[str, Any]]:
        """Return scopes grouped by resource for compact UI display.

        Turns ``["streams:read", "streams:write", "api:read"]`` into
        ``[{"resource": "streams", "actions": ["read", "write"],
            "short": "r/w"},
           {"resource": "api", "actions": ["read"], "short": "r"}]``.

        The ``short`` field collapses common action names to single
        letters (r=read, w=write, d=delete, a=admin) so a fully-
        granted key renders as a handful of chips instead of a wall.
        Resources appear in the order first encountered in scope_list.
        """
        action_abbrev = {
            "read": "r",
            "write": "w",
            "delete": "d",
            "admin": "a",
        }
        seen: List[str] = []
        buckets: Dict[str, List[str]] = {}
        for scope in self.scope_list():
            if ":" not in scope:
                continue
            resource, action = scope.split(":", 1)
            if resource not in buckets:
                buckets[resource] = []
                seen.append(resource)
            if action not in buckets[resource]:
                buckets[resource].append(action)
        groups: List[Dict[str, Any]] = []
        for resource in seen:
            actions = buckets[resource]
            short = "/".join(
                action_abbrev.get(a, a[:1]) for a in actions
            )
            groups.append(
                {
                    "resource": resource,
                    "actions": actions,
                    "short": short,
                }
            )
        return groups

    def has_scope(self, resource: str, action: str) -> bool:
        """True when the key's scope list includes ``resource:action``."""
        return f"{resource}:{action}" in self.scope_list()

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for API responses. Never includes hash/salt."""
        return {
            "id": self.id,
            "name": self.name,
            "prefix": self.token_prefix,
            "scopes": self.scope_list(),
            "scope_groups": self.scope_groups(),
            "expires_at": (
                self.expires_at.isoformat() if self.expires_at else None
            ),
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "revoked_at": (
                self.revoked_at.isoformat() if self.revoked_at else None
            ),
            "is_active": self.is_active,
            "is_valid": self.is_valid(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
