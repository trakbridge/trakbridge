"""
ABOUTME: Authentication routes for login, logout, and SSO callback handling
ABOUTME: Provides web interface for multi-provider authentication in TrakBridge

File: routes/auth.py

Description:
    Authentication routes blueprint providing web interface for user authentication
    in TrakBridge. Handles login/logout flows for all authentication providers (Local,
    LDAP, OIDC), OIDC callback processing, session management, and user profile
    functionality. Integrates with the authentication manager for seamless
    multi-provider authentication experience.

Key features:
    - Universal login page with provider selection
    - Local username/password authentication
    - OIDC SSO authentication with redirect handling
    - LDAP authentication integration
    - Secure logout with session invalidation
    - User profile management and password changes
    - Admin user management interface
    - Session security and CSRF protection
    - Comprehensive error handling and user feedback

Author: Emfour Solutions
Created: 2025-07-26
"""

# Standard library imports
from datetime import datetime, timezone

# Third-party imports
from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Local application imports
from models.user import AuthProvider, User, UserRole
from services.auth import (
    AuthenticationManager,
    LDAPAuthProvider,
    LocalAuthProvider,
    OIDCAuthProvider,
    admin_required,
    get_current_user,
    logout_user,
    require_auth,
    session_only,
)
from services.auth.base_provider import AuthenticationResult

# Module-level logger
from services.logging_service import get_module_logger

logger = get_module_logger(__name__)

# Create blueprint
bp = Blueprint("auth", __name__, url_prefix="/auth")


def get_auth_manager() -> AuthenticationManager:
    """Get authentication manager from app context"""
    return getattr(current_app, "auth_manager", None)


@bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Universal login page supporting all authentication providers
    """
    # Check if already authenticated
    if get_current_user():
        next_url = session.pop("next_url", url_for("main.index"))
        return redirect(next_url)

    auth_manager = get_auth_manager()
    if not auth_manager:
        flash("Authentication system not available", "error")
        return render_template("auth/error.html"), 500

    # Get available providers
    providers_info = auth_manager.get_provider_info()
    enabled_providers = {
        k: v for k, v in providers_info.items() if v.get("enabled", False)
    }

    if request.method == "GET":
        return render_template("auth/login.html", providers=enabled_providers)

    # Handle POST request
    auth_method = request.form.get("auth_method", "local")

    if auth_method == "local":
        return _handle_local_login(auth_manager)
    elif auth_method == "ldap":
        return _handle_ldap_login(auth_manager)
    elif auth_method == "oidc":
        return _handle_oidc_login(auth_manager)
    else:
        flash("Invalid authentication method", "error")
        return render_template("auth/login.html", providers=enabled_providers)


def _handle_local_login(auth_manager: AuthenticationManager):
    """Handle local authentication"""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for("auth.login"))

    # Get request info for session creation
    request_info = {
        "ip_address": request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
    }

    # Authenticate user
    response = auth_manager.authenticate(username, password)

    if response.success:
        # CRITICAL: Regenerate session ID to prevent session fixation
        # Save any data we want to preserve
        next_url = session.get('next_url')

        # Clear old session completely
        session.clear()

        # Restore preserved data
        if next_url:
            session['next_url'] = next_url

        # Check if password change is required
        from services.auth.bootstrap_service import check_password_change_required

        if check_password_change_required(response.user):
            # Store user info in session for password change
            session["password_change_user_id"] = response.user.id
            logger.info(
                f"User {response.user.username} requires password change, redirecting to force_password_change"
            )
            flash(
                "Initial setup required: Please set a new password for your admin account",
                "info",
            )
            return redirect(url_for("auth.force_password_change"))

        # Create session with new ID
        user_session = auth_manager.create_session(
            response.user, AuthProvider.LOCAL, request_info
        )

        # Set new session ID
        session["session_id"] = user_session.session_id
        session.permanent = True

        logger.info(f"Session regenerated for {response.user.username}")

        flash(
            f"Welcome, {response.user.full_name or response.user.username}!", "success"
        )

        # Redirect to next URL or dashboard
        next_url = session.pop("next_url", url_for("main.index"))
        return redirect(next_url)
    elif response.result == AuthenticationResult.PASSWORD_EXPIRED:
        session["password_change_user_id"] = response.user.id
        logger.info(
            f"User {response.user.username} has an expired password, redirecting to force_password_change"
        )
        flash(
            "Your password has expired. Please set a new password to continue.",
            "warning",
        )
        return redirect(url_for("auth.force_password_change"))
    else:
        flash(response.message, "error")
        return redirect(url_for("auth.login"))


def _handle_ldap_login(auth_manager: AuthenticationManager):
    """Handle LDAP authentication"""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for("auth.login"))

    # Get request info for session creation
    request_info = {
        "ip_address": request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
    }

    # Authenticate user with provider hint
    response = auth_manager.authenticate(
        username, password, provider_hint=AuthProvider.LDAP
    )

    if response.success:
        # CRITICAL: Regenerate session ID to prevent session fixation
        # Save any data we want to preserve
        next_url = session.get('next_url')

        # Clear old session completely
        session.clear()

        # Restore preserved data
        if next_url:
            session['next_url'] = next_url

        # Create session with new ID
        user_session = auth_manager.create_session(
            response.user, AuthProvider.LDAP, request_info
        )

        # Set new session ID
        session["session_id"] = user_session.session_id
        session.permanent = True

        logger.info(f"Session regenerated for {response.user.username}")

        flash(
            f"Welcome, {response.user.full_name or response.user.username}!", "success"
        )

        # Redirect to next URL or dashboard
        next_url = session.pop("next_url", url_for("main.index"))
        return redirect(next_url)
    else:
        flash(response.message, "error")
        return redirect(url_for("auth.login"))


def _handle_oidc_login(auth_manager: AuthenticationManager):
    """Handle OIDC authentication initiation"""
    try:
        # Get OIDC provider
        oidc_provider = None
        for provider_type, provider in auth_manager.providers.items():
            if provider_type == AuthProvider.OIDC and provider.enabled:
                oidc_provider = provider
                break

        if not oidc_provider:
            flash("OIDC authentication is not available", "error")
            return redirect(url_for("auth.login"))

        # Generate state for CSRF protection
        import secrets

        state = secrets.token_urlsafe(32)
        session["oidc_state"] = state

        # Build redirect URI using secure configured URL to prevent host header injection
        from flask import current_app

        redirect_uri = f"{current_app.config['APPLICATION_URL']}/auth/oidc/callback"

        # Get authorization URL
        auth_url, state = oidc_provider.get_authorization_url(redirect_uri, state)

        logger.info("Redirecting to OIDC provider for authentication")
        return redirect(auth_url)

    except Exception as e:
        logger.error(f"OIDC login error: {e}")
        flash("Error initiating SSO authentication", "error")
        return redirect(url_for("auth.login"))


@bp.route("/oidc/callback")
def oidc_callback():
    """
    Handle OIDC callback after authentication
    """
    auth_manager = get_auth_manager()
    if not auth_manager:
        flash("Authentication system not available", "error")
        return redirect(url_for("auth.login"))

    # Get parameters from callback
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    # Handle errors
    if error:
        error_description = request.args.get("error_description", "Unknown error")
        logger.warning(f"OIDC callback error: {error} - {error_description}")
        flash(f"Authentication failed: {error_description}", "error")
        return redirect(url_for("auth.login"))

    # Validate state parameter
    expected_state = session.pop("oidc_state", None)
    if not state or state != expected_state:
        logger.warning("OIDC callback state mismatch - possible CSRF attack")
        flash("Authentication failed: Invalid state parameter", "error")
        return redirect(url_for("auth.login"))

    if not code:
        flash("Authentication failed: No authorization code received", "error")
        return redirect(url_for("auth.login"))

    try:
        # Get OIDC provider
        oidc_provider = None
        for provider_type, provider in auth_manager.providers.items():
            if provider_type == AuthProvider.OIDC and provider.enabled:
                oidc_provider = provider
                break

        if not oidc_provider:
            flash("OIDC authentication is not available", "error")
            return redirect(url_for("auth.login"))

        # Authenticate with authorization code
        response = oidc_provider.authenticate(authorization_code=code, state=state)

        if response.success:
            # CRITICAL: Regenerate session ID to prevent session fixation
            # Save any data we want to preserve
            next_url = session.get('next_url')

            # Clear old session completely (state already popped above)
            session.clear()

            # Restore preserved data
            if next_url:
                session['next_url'] = next_url

            # Get request info for session creation
            request_info = {
                "ip_address": request.environ.get(
                    "HTTP_X_FORWARDED_FOR", request.remote_addr
                ),
                "user_agent": request.headers.get("User-Agent", ""),
                "provider_session_data": response.session_data,
            }

            # Create session with new ID
            user_session = auth_manager.create_session(
                response.user, AuthProvider.OIDC, request_info
            )

            # Set new session ID
            session["session_id"] = user_session.session_id
            session.permanent = True

            logger.info(f"Session regenerated for {response.user.username}")

            flash(
                f"Welcome, {response.user.full_name or response.user.username}!",
                "success",
            )

            # Redirect to next URL or dashboard
            next_url = session.pop("next_url", url_for("main.index"))
            return redirect(next_url)
        else:
            flash(response.message, "error")
            return redirect(url_for("auth.login"))

    except Exception as e:
        logger.error(f"OIDC callback error: {e}", exc_info=True)
        flash("Authentication failed: System error", "error")
        return redirect(url_for("auth.login"))


@bp.route("/logout")
@session_only
def logout():
    """
    Log out current user
    """
    user = get_current_user()
    if user:
        logger.info(f"User {user.username} logging out")

    # Logout user (invalidates session)
    logout_user()

    flash("You have been logged out successfully", "info")
    return redirect(url_for("auth.login"))


@bp.route("/profile")
@require_auth
def profile():
    """
    User profile page
    """
    user = get_current_user()
    return render_template("auth/profile.html", user=user)


@bp.route("/profile/edit", methods=["GET", "POST"])
@session_only
@require_auth
def edit_profile():
    """
    Edit user profile
    """
    user = get_current_user()

    if request.method == "GET":
        return render_template("auth/edit_profile.html", user=user)

    # Handle POST request
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    timezone = request.form.get("timezone", "UTC")
    language = request.form.get("language", "en")

    try:
        # Update user info
        user.full_name = full_name
        user.email = email
        user.timezone = timezone
        user.language = language

        from database import db

        db.session.commit()

        flash("Profile updated successfully", "success")
        return redirect(url_for("auth.profile"))

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to update profile for {user.username}: {e}")
        flash("Error updating profile", "error")
        return render_template("auth/edit_profile.html", user=user)


@bp.route("/change-password", methods=["GET", "POST"])
@session_only
@require_auth
def change_password():
    """
    Change user password (local auth only)
    """
    user = get_current_user()

    # Only allow password changes for local auth users
    if user.auth_provider != AuthProvider.LOCAL:
        flash(
            "Password changes are not supported for your authentication method",
            "warning",
        )
        return redirect(url_for("auth.profile"))

    if request.method == "GET":
        return render_template("auth/change_password.html")

    # Handle POST request
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        flash("All fields are required", "error")
        return render_template("auth/change_password.html")

    if new_password != confirm_password:
        flash("New passwords do not match", "error")
        return render_template("auth/change_password.html")

    try:
        # Get local auth provider
        auth_manager = get_auth_manager()
        local_provider = None

        for provider_type, provider in auth_manager.providers.items():
            if provider_type == AuthProvider.LOCAL:
                local_provider = provider
                break

        if not local_provider:
            flash("Local authentication is not available", "error")
            return redirect(url_for("auth.profile"))

        # Change password
        success = local_provider.change_password(
            user.username, current_password, new_password
        )

        if success:
            flash("Password changed successfully", "success")
            return redirect(url_for("auth.profile"))
        else:
            flash("Failed to change password", "error")
            return render_template("auth/change_password.html")

    except Exception as e:
        logger.error(f"Password change error for {user.username}: {e}")
        flash(str(e), "error")
        return render_template("auth/change_password.html")


@bp.route("/admin/users")
@session_only
@admin_required
def admin_users():
    """
    Admin page for user management
    """
    users = User.query.order_by(User.created_at.desc()).all()

    # Get authentication stats
    auth_manager = get_auth_manager()
    stats = auth_manager.get_authentication_stats() if auth_manager else {}

    return render_template("auth/admin_users.html", users=users, stats=stats)


@bp.route("/admin/users/<int:user_id>")
@session_only
@admin_required
def admin_user_detail(user_id):
    """
    Admin page for individual user details
    """
    user = User.query.get_or_404(user_id)

    # Get user sessions
    active_sessions = [s for s in user.sessions if s.is_active]

    return render_template(
        "auth/admin_user_detail.html", user=user, active_sessions=active_sessions
    )


@bp.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@session_only
@admin_required
def admin_disable_user(user_id):
    """
    Admin function to disable a user
    """
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    # Prevent disabling self
    if user.id == current_user.id:
        flash("You cannot disable your own account", "error")
        return redirect(url_for("auth.admin_user_detail", user_id=user_id))

    try:
        from models.user import AccountStatus

        user.status = AccountStatus.DISABLED

        # Invalidate all user sessions
        auth_manager = get_auth_manager()
        if auth_manager:
            auth_manager.invalidate_all_user_sessions(user.id)

        from database import db

        db.session.commit()

        logger.info(f"Admin {current_user.username} disabled user {user.username}")
        flash(f"User {user.username} has been disabled", "success")

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to disable user {user.username}: {e}")
        flash("Error disabling user", "error")

    return redirect(url_for("auth.admin_user_detail", user_id=user_id))


@bp.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@session_only
@admin_required
def admin_enable_user(user_id):
    """
    Admin function to enable a user
    """
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    try:
        from models.user import AccountStatus

        user.status = AccountStatus.ACTIVE
        user.unlock_account()  # Also unlock if locked

        from database import db

        db.session.commit()

        logger.info(f"Admin {current_user.username} enabled user {user.username}")
        flash(f"User {user.username} has been enabled", "success")

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to enable user {user.username}: {e}")
        flash("Error enabling user", "error")

    return redirect(url_for("auth.admin_user_detail", user_id=user_id))


@bp.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@session_only
@admin_required
def admin_unlock_user(user_id):
    """Admin function to clear a lockout on a user account.

    Unlike enable, this does not change the user's status — it only
    clears failed_login_attempts and locked_until. Intended for
    locked-but-active accounts (e.g. an operator whose password was
    fat-fingered too many times).
    """
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if not user.is_locked():
        flash(f"User {user.username} was not locked", "info")
        return redirect(url_for("auth.admin_user_detail", user_id=user_id))

    try:
        user.unlock_account()

        from database import db

        db.session.commit()

        logger.info(
            f"Admin {current_user.username} unlocked user {user.username}"
        )
        flash(f"User {user.username} has been unlocked", "success")

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to unlock user {user.username}: {e}")
        flash("Error unlocking user", "error")

    return redirect(url_for("auth.admin_user_detail", user_id=user_id))


@bp.route("/admin/users/create", methods=["GET", "POST"])
@session_only
@admin_required
def admin_create_user():
    """
    Admin function to create a new user (local only)
    """
    if request.method == "GET":
        return render_template("auth/admin_create_user.html")

    # Handle POST request
    try:
        # Get form data
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role_str = request.form.get("role", "user")

        # Validation
        if not username:
            flash("Username is required", "error")
            return render_template("auth/admin_create_user.html")

        if not password:
            flash("Password is required", "error")
            return render_template("auth/admin_create_user.html")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("auth/admin_create_user.html")

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f'Username "{username}" already exists', "error")
            return render_template("auth/admin_create_user.html")

        # Check if email already exists (if provided)
        if email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash(f'Email "{email}" is already in use', "error")
                return render_template("auth/admin_create_user.html")

        # Validate role
        try:
            role = UserRole(role_str)
        except ValueError:
            flash("Invalid role selected", "error")
            return render_template("auth/admin_create_user.html")

        # Create the user
        user = User.create_local_user(
            username=username,
            password=password,
            email=email if email else None,
            full_name=full_name if full_name else None,
            role=role,
        )

        from database import db

        db.session.add(user)
        db.session.commit()

        current_user = get_current_user()
        logger.info(
            f"Admin {current_user.username} created user {username} with role {role.value}"
        )
        flash(f'User "{username}" created successfully', "success")

        return redirect(url_for("auth.admin_users"))

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to create user: {e}")
        flash("Error creating user. Please try again.", "error")
        return render_template("auth/admin_create_user.html")


@bp.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@session_only
@admin_required
def admin_edit_user(user_id):
    """
    Admin function to edit a user
    """
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if request.method == "GET":
        return render_template("auth/admin_edit_user.html", user=user)

    # Handle POST request
    try:
        # Get form data
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        role_str = request.form.get("role")

        # Check if email already exists (if changed and provided)
        if email and email != user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash(f'Email "{email}" is already in use', "error")
                return render_template("auth/admin_edit_user.html", user=user)

        # Validate role change
        if role_str and role_str != user.role.value:
            try:
                new_role = UserRole(role_str)

                # Prevent self role change
                if user.id == current_user.id:
                    flash("You cannot change your own role", "error")
                    return render_template("auth/admin_edit_user.html", user=user)

                # Prevent removing last admin
                if user.role == UserRole.ADMIN and new_role != UserRole.ADMIN:
                    admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
                    if admin_count <= 1:
                        flash(
                            "Cannot remove admin role from the last administrator",
                            "error",
                        )
                        return render_template("auth/admin_edit_user.html", user=user)

                user.role = new_role
                logger.info(
                    f"Admin {current_user.username} changed user {user.username} role to {new_role.value}"
                )

            except ValueError:
                flash("Invalid role selected", "error")
                return render_template("auth/admin_edit_user.html", user=user)

        # Update user information (only for local users or allowed fields)
        if user.auth_provider == AuthProvider.LOCAL or email or full_name:
            if email:
                user.email = email
            if full_name:
                user.full_name = full_name

        from database import db

        db.session.commit()

        logger.info(f"Admin {current_user.username} updated user {user.username}")
        flash(f'User "{user.username}" updated successfully', "success")

        return redirect(url_for("auth.admin_user_detail", user_id=user.id))

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to update user {user.username}: {e}")
        flash("Error updating user. Please try again.", "error")
        return render_template("auth/admin_edit_user.html", user=user)


@bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@session_only
@admin_required
def admin_reset_password(user_id):
    """
    Admin function to reset a user's password (local users only)
    """
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    # Only allow for local users
    if user.auth_provider != AuthProvider.LOCAL:
        flash("Cannot reset password for external authentication users", "error")
        return redirect(url_for("auth.admin_user_detail", user_id=user.id))

    try:
        # Generate a secure temporary password
        import secrets
        import string

        # Generate secure temporary password
        alphabet = string.ascii_letters + string.digits + "!@#$%&*"
        temp_password = "".join(secrets.choice(alphabet) for _ in range(12))

        # Reset password and flag that a change is required on next login.
        # We keep password_changed_at as a real timestamp (set by set_password)
        # rather than None so that the expiry check does not immediately expire
        # the account if password-age enforcement is enabled.
        user.set_password(temp_password)
        user.must_change_password = True

        from database import db

        db.session.commit()

        logger.info(
            f"Admin {current_user.username} reset password for user {user.username}"
        )
        flash(
            f'Password reset for "{user.username}". Temporary password: {temp_password}',
            "warning",
        )
        flash("User must change password on next login", "info")

        return redirect(url_for("auth.admin_user_detail", user_id=user.id))

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to reset password for user {user.username}: {e}")
        flash("Error resetting password. Please try again.", "error")
        return redirect(url_for("auth.admin_user_detail", user_id=user.id))


@bp.route("/force-password-change", methods=["GET", "POST"])
@session_only
def force_password_change():
    """
    Force password change for users who need to update their password
    """
    user_id = session.get("password_change_user_id")
    if not user_id:
        logger.warning(
            "force_password_change accessed without password_change_user_id in session"
        )
        flash("No password change required", "info")
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.pop("password_change_user_id", None)
        logger.error(
            f"force_password_change: User with ID {user_id} not found in database"
        )
        flash("User not found", "error")
        return redirect(url_for("auth.login"))

    logger.info(
        f"force_password_change: Loading password change form for user {user.username}"
    )

    if request.method == "GET":
        return render_template("auth/force_password_change.html", user=user)

    # Handle POST request
    try:
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not current_password or not new_password or not confirm_password:
            flash("All fields are required", "error")
            return render_template("auth/force_password_change.html", user=user)

        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return render_template("auth/force_password_change.html", user=user)

        # Verify current password
        if not user.check_password(current_password):
            flash("Current password is incorrect", "error")
            return render_template("auth/force_password_change.html", user=user)

        # Change password and clear any forced-change flag
        user.set_password(new_password)
        user.must_change_password = False

        from database import db

        db.session.commit()

        # Clear password change session
        session.pop("password_change_user_id", None)

        logger.info(f"User {user.username} completed forced password change")
        flash("Password changed successfully. You can now continue.", "success")

        # Now create the session and log the user in
        auth_manager = get_auth_manager()
        if auth_manager:
            request_info = {
                "ip_address": request.environ.get(
                    "HTTP_X_FORWARDED_FOR", request.remote_addr
                ),
                "user_agent": request.headers.get("User-Agent", ""),
            }

            user_session = auth_manager.create_session(
                user, AuthProvider.LOCAL, request_info
            )

            session["session_id"] = user_session.session_id
            session.permanent = True

        # Redirect to dashboard
        return redirect(url_for("main.index"))

    except Exception as e:
        from database import db

        db.session.rollback()
        logger.error(f"Failed to change password for user {user.username}: {e}")
        flash("Error changing password. Please try again.", "error")
        return render_template("auth/force_password_change.html", user=user)


@bp.route("/api/session/check")
def check_session():
    """
    API endpoint to check session validity
    """
    user = get_current_user()

    if user:
        return jsonify(
            {
                "authenticated": True,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "role": user.role.value,
                    "auth_provider": user.auth_provider.value,
                },
            }
        )
    else:
        return jsonify({"authenticated": False}), 401


@bp.route("/api/logout", methods=["POST"])
@session_only
def api_logout():
    """
    API endpoint for logout
    """
    logout_user()
    return jsonify({"success": True, "message": "Logged out successfully"})


# Error handlers for auth blueprint
@bp.errorhandler(401)
def auth_unauthorized(error):
    """Handle unauthorized access"""
    if request.is_json:
        return (
            jsonify(
                {
                    "error": "Unauthorized",
                    "message": "Authentication required",
                    "status": 401,
                }
            ),
            401,
        )
    else:
        flash("Please log in to access this page", "warning")
        session["next_url"] = request.url
        return redirect(url_for("auth.login"))


@bp.errorhandler(403)
def auth_forbidden(error):
    """Handle forbidden access"""
    if request.is_json:
        return (
            jsonify(
                {
                    "error": "Forbidden",
                    "message": "Insufficient permissions",
                    "status": 403,
                }
            ),
            403,
        )
    else:
        flash("You do not have permission to access this page", "error")
        return redirect(url_for("main.index"))
