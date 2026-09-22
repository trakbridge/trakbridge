"""
ABOUTME: LDAP/Active Directory authentication provider for enterprise directory integration
ABOUTME: Supports LDAP/LDAPS with SSL/TLS and group-based role mapping

File: services/auth/ldap_provider.py

Description:
    LDAP authentication provider for integration with Active Directory and other LDAP
    directories. Supports secure LDAP/LDAPS connections, user authentication, group
    membership retrieval, and flexible role mapping. Provides comprehensive error
    handling and connection management for enterprise directory integration.

Key features:
    - LDAP/LDAPS authentication with SSL/TLS support
    - Active Directory and generic LDAP compatibility
    - Group membership and role mapping
    - Configurable user attribute mapping
    - Connection pooling and error recovery
    - DN-based and simple authentication modes
    - User information synchronization
    - Comprehensive health monitoring
    - Security controls and input validation

Author: Emfour Solutions
Created: 2025-07-26
"""

# Standard library imports
import importlib.util
import logging
import re
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

# Local application imports
from models.user import AuthProvider, User, UserRole
from services.logging_service import get_module_logger
from utils.config_helpers import ConfigHelper

from .base_provider import (
    AuthenticationException,
    AuthenticationResponse,
    AuthenticationResult,
    BaseAuthenticationProvider,
    ProviderConfigurationException,
    ProviderConnectionException,
)

# Third-party imports
LDAP3_AVAILABLE = importlib.util.find_spec("ldap3") is not None

if LDAP3_AVAILABLE:
    import ldap3
    from ldap3 import ALL, SUBTREE, Connection, Server
    from ldap3.core.exceptions import LDAPBindError, LDAPException
else:
    ldap3 = None


# Module-level logger
logger = get_module_logger(__name__)


class LDAPAuthProvider(BaseAuthenticationProvider):
    """
    LDAP authentication provider for Active Directory and LDAP directories
    """

    def __init__(self, config: Dict[str, Any] = None):
        if not LDAP3_AVAILABLE:
            raise ProviderConfigurationException(
                "ldap3 library is not available. Install with: pip install ldap3"
            )

        # Initialize config if not provided
        config = config or {}

        # Server configuration - handle both old nested format and new flat format
        # (Must be done before calling super().__init__ because validation runs there)
        server_config = config.get("server", {})
        if isinstance(server_config, dict) and server_config:
            # Old nested format: server: { host: ..., port: ... }
            self.host = server_config.get("host", "localhost")
            self.port = server_config.get("port", 636)
            self.use_ssl = server_config.get("use_ssl", True)
            self.use_tls = server_config.get("use_tls", False)
            self.timeout = server_config.get("timeout", 30)
        else:
            # New flat format: server: "ldap://host", port: 389, use_ssl: false
            server_url = config.get("server", "ldap://localhost")
            if "://" in server_url:
                protocol, host_part = server_url.split("://", 1)
                self.host = host_part
                self.use_ssl = protocol == "ldaps"
            else:
                self.host = server_url
                self.use_ssl = config.get("use_ssl", True)

            self.port = config.get("port", 636 if self.use_ssl else 389)
            self.use_tls = config.get("use_tls", False)
            self.timeout = config.get("connection_timeout", 30)

        # Bind configuration
        self.bind_dn = config.get("bind_dn", "")
        self.bind_password = config.get("bind_password", "")

        # User search configuration - using ConfigHelper for cleaner access
        helper = ConfigHelper(config)
        self.user_base_dn = helper.get(
            "user_search.base_dn", helper.get("user_search_base", "")
        )
        self.user_search_filter = helper.get(
            "user_search.search_filter",
            helper.get("user_search_filter", "(sAMAccountName={username})"),
        )
        self.user_attributes = helper.get(
            "user_search.attributes", helper.get("attributes", {})
        )

        # Attribute mapping
        self.username_attr = self.user_attributes.get("username", "sAMAccountName")
        self.email_attr = self.user_attributes.get("email", "mail")
        self.full_name_attr = self.user_attributes.get("full_name", "displayName")
        self.first_name_attr = self.user_attributes.get("first_name", "givenName")
        self.last_name_attr = self.user_attributes.get("last_name", "sn")
        self.groups_attr = self.user_attributes.get("groups", "memberOf")

        # Group and role mapping
        self.group_mappings = config.get("group_mappings", {}) or config.get(
            "role_mapping", {}
        )
        self.default_role = UserRole(config.get("default_role", "user"))

        # TLS certificate validation settings
        self.validate_cert = config.get("validate_cert", True)
        self.ca_cert_file = config.get("ca_cert_file", None)
        # Treat "null" string (from YAML env substitution) as None
        if self.ca_cert_file in (None, "", "null"):
            self.ca_cert_file = None

        # T4.1: allow the operator to run LDAP over plaintext, but only
        # as a deliberate, auditable opt-in. Default False. When True
        # the validator lets the config through and every startup emits
        # a WARNING naming the server.
        self.allow_insecure = bool(config.get("allow_insecure", False))

        # Settings
        self.auto_create_users = config.get("auto_create_users", True)
        self.update_user_info = config.get("update_user_info", True)

        # Now call parent constructor which will validate configuration
        super().__init__(AuthProvider.LDAP, config)

        # Initialize server
        self._server = None
        self._initialize_server()

        # T4.1: if the operator opted into an insecure configuration,
        # make sure every startup announces it so it's visible in log
        # scrapers and the operator can't forget it's on.
        if self.allow_insecure:
            insecure_bits = []
            if not self.use_ssl and not self.use_tls:
                insecure_bits.append("plaintext bind on port %d" % self.port)
            if (self.use_ssl or self.use_tls) and not self.validate_cert:
                insecure_bits.append("cert validation disabled")
            logger.warning(
                "LDAP allow_insecure=true — %s. Credentials may be "
                "read or intercepted on the network path to %s:%d.",
                "; ".join(insecure_bits) or "insecure options set",
                self.host,
                self.port,
            )

        logger.info(
            f"LDAP authentication provider initialized (server: {self.host}:{self.port})"
        )

    def _initialize_server(self) -> None:
        """Initialize LDAP server connection"""
        try:
            # Build server URL
            protocol = "ldaps" if self.use_ssl else "ldap"
            server_uri = f"{protocol}://{self.host}:{self.port}"

            # SSL/TLS configuration
            tls_config = None
            if self.use_ssl or self.use_tls:
                tls_kwargs = {
                    "validate": (
                        ssl.CERT_REQUIRED
                        if self.validate_cert
                        else ssl.CERT_NONE
                    ),
                    "version": ssl.PROTOCOL_TLS,
                    "ciphers": "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
                }
                if self.ca_cert_file:
                    tls_kwargs["ca_certs_file"] = self.ca_cert_file
                tls_config = ldap3.Tls(**tls_kwargs)

                logger.debug(
                    f"LDAP TLS config: validate_cert={self.validate_cert}, "
                    f"ca_cert_file={self.ca_cert_file}"
                )

            # Create server
            self._server = Server(
                host=self.host,
                port=self.port,
                use_ssl=self.use_ssl,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            logger.debug(f"LDAP server initialized: {server_uri}")

        except Exception as e:
            logger.error(f"Failed to initialize LDAP server: {e}")
            raise ProviderConfigurationException(
                f"LDAP server initialization failed: {e}"
            )

    def authenticate(
        self, username: str, password: str = None, **kwargs
    ) -> AuthenticationResponse:
        """
        Authenticate user against LDAP directory

        Args:
            username: Username to authenticate
            password: Password to verify
            **kwargs: Additional parameters

        Returns:
            AuthenticationResponse with authentication result
        """
        if not username or not password:
            return AuthenticationResponse(
                result=AuthenticationResult.INVALID_CREDENTIALS,
                message="Username and password are required",
            )

        try:
            # First, search for the user to get their DN
            user_info = self._search_user(username)

            if not user_info:
                logger.warning(f"LDAP user not found: {username}")
                return AuthenticationResponse(
                    result=AuthenticationResult.USER_NOT_FOUND,
                    message="User not found in directory",
                )

            user_dn = user_info.get("dn")
            if not user_dn:
                logger.error(f"No DN found for LDAP user: {username}")
                return AuthenticationResponse(
                    result=AuthenticationResult.PROVIDER_ERROR,
                    message="User DN not found",
                )

            # Attempt to bind with user credentials
            if not self._authenticate_user(user_dn, password):
                logger.warning(f"LDAP authentication failed for user: {username}")
                return AuthenticationResponse(
                    result=AuthenticationResult.INVALID_CREDENTIALS,
                    message="Invalid credentials",
                )

            # Authentication successful, create or update user
            user = None
            if self.auto_create_users:
                try:
                    user = self._create_or_update_user(username, user_info)
                except Exception as e:
                    logger.error(f"Failed to create/update user {username}: {e}")
                    return AuthenticationResponse(
                        result=AuthenticationResult.PROVIDER_ERROR,
                        message="User management error",
                        details={"error": str(e)},
                    )
            else:
                # Find existing user
                user = User.query.filter_by(
                    username=username, auth_provider=AuthProvider.LDAP
                ).first()

                if not user:
                    return AuthenticationResponse(
                        result=AuthenticationResult.USER_NOT_FOUND,
                        message="User not found in local database",
                    )

                # Update user info if configured
                if self.update_user_info:
                    user.update_from_provider(user_info)
                    try:
                        from database import db

                        db.session.commit()
                    except Exception as e:
                        logger.error(f"Failed to update user info: {e}")

            logger.info(f"Successful LDAP authentication for user: {username}")
            return AuthenticationResponse(
                result=AuthenticationResult.SUCCESS,
                user=user,
                message="Authentication successful",
                details={"provider": "ldap", "groups": user_info.get("groups", [])},
            )

        except LDAPBindError:
            logger.warning(f"LDAP invalid credentials for user: {username}")
            return AuthenticationResponse(
                result=AuthenticationResult.INVALID_CREDENTIALS,
                message="Invalid credentials",
            )

        except LDAPException as e:
            logger.error(f"LDAP error during authentication for {username}: {e}")
            return AuthenticationResponse(
                result=AuthenticationResult.NETWORK_ERROR,
                message="Directory service error",
                details={"ldap_error": str(e)},
            )

        except Exception as e:
            logger.error(
                f"LDAP authentication error for {username}: {e}", exc_info=True
            )
            return AuthenticationResponse(
                result=AuthenticationResult.PROVIDER_ERROR,
                message="Authentication service error",
                details={"error": str(e)},
            )

    def get_user_info(self, username: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Get user information from LDAP directory

        Args:
            username: Username to look up
            **kwargs: Additional parameters

        Returns:
            Dictionary with user information or None if not found
        """
        try:
            return self._search_user(username)
        except Exception as e:
            logger.error(f"Error getting LDAP user info for {username}: {e}")
            return None

    def validate_configuration(self) -> List[str]:
        """
        Validate LDAP provider configuration

        Returns:
            List of configuration issues
        """
        issues = []

        # Check required settings
        if not self.host:
            issues.append("LDAP host is required")

        if not self.port or not isinstance(self.port, int):
            issues.append("LDAP port must be a valid integer")

        if not self.user_base_dn:
            issues.append("User base DN is required")

        if not self.user_search_filter:
            issues.append("User search filter is required")

        # Validate search filter
        if "{username}" not in self.user_search_filter:
            issues.append("User search filter must contain {username} placeholder")

        # Check bind credentials if provided
        if self.bind_dn and not self.bind_password:
            issues.append("Bind password is required when bind DN is specified")

        # Validate default role
        try:
            UserRole(self.config.get("default_role", "user"))
        except ValueError:
            issues.append(f"Invalid default_role: {self.config.get('default_role')}")

        # Check SSL/TLS configuration
        if self.use_ssl and self.use_tls:
            issues.append("Cannot use both SSL and TLS - choose one")

        if self.use_ssl and self.port == 389:
            issues.append("SSL typically uses port 636, not 389")

        if not self.use_ssl and not self.use_tls and self.port == 636:
            issues.append("Port 636 typically requires SSL")

        # T4.1: refuse plaintext LDAP unless the operator has explicitly
        # opted in via allow_insecure=true. Prior behaviour let
        # use_tls=false, use_ssl=false ship silently, sending the
        # service bind password and every user password in cleartext.
        if not self.use_ssl and not self.use_tls and not self.allow_insecure:
            issues.append(
                "LDAP must use LDAPS (use_ssl=true) or StartTLS "
                "(use_tls=true) — plaintext bind exposes credentials. "
                "To knowingly run plaintext LDAP set allow_insecure=true "
                "in the provider config."
            )

        # TLS enabled but cert validation disabled is a MITM risk —
        # validate_cert=false is legal but requires the same explicit
        # opt-in to keep operators honest.
        if (
            (self.use_ssl or self.use_tls)
            and not self.validate_cert
            and not self.allow_insecure
        ):
            issues.append(
                "LDAP TLS is enabled but validate_cert=false — this "
                "disables certificate verification and defeats TLS. "
                "Set allow_insecure=true to acknowledge the risk."
            )

        return issues

    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check for LDAP provider

        Returns:
            Dictionary with health status
        """
        try:
            # Test basic connection
            connection = self._get_connection()

            if not connection.bind():
                raise LDAPException(f"Failed to bind: {connection.result}")

            # Test user search
            search_base = self.user_base_dn
            search_filter = "(objectClass=*)"

            success = connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                size_limit=1,
            )

            connection.unbind()

            if not success:
                raise LDAPException("Search test failed")

            return {
                "status": "healthy",
                "provider": "ldap",
                "server": f"{self.host}:{self.port}",
                "ssl_enabled": self.use_ssl,
                "tls_enabled": self.use_tls,
                "validate_cert": self.validate_cert,
                "base_dn": self.user_base_dn,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except LDAPException as e:
            # Log detailed LDAP error for debugging
            logger.error(f"LDAP health check failed with detailed error: {str(e)}")
            logger.error(f"LDAP bind DN: {self.bind_dn}")
            logger.error(
                f"LDAP server: {self.host}:{self.port} (SSL: {self.use_ssl}, TLS: {self.use_tls})"
            )
            logger.error(
                f"LDAP bind password configured: {'Yes' if self.bind_password else 'No'}"
            )
            logger.error(
                f"LDAP bind password length: {len(self.bind_password) if self.bind_password else 0} chars"
            )
            return {
                "status": "unhealthy",
                "provider": "ldap",
                "server": f"{self.host}:{self.port}",
                "error": f"LDAP error: {str(e)}",
                "bind_dn": self.bind_dn,
                "ssl_enabled": self.use_ssl,
                "tls_enabled": self.use_tls,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "ldap",
                "server": f"{self.host}:{self.port}",
                "error": f"Connection error: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _get_connection(self, user_dn: str = None, password: str = None) -> Connection:
        """
        Get LDAP connection

        Args:
            user_dn: User DN for binding (optional)
            password: User password for binding (optional)

        Returns:
            LDAP connection object
        """
        if user_dn and password:
            # User authentication connection
            connection = Connection(
                self._server,
                user=user_dn,
                password=password,
                auto_bind=False,
                raise_exceptions=True,
            )
        elif self.bind_dn and self.bind_password:
            # Service account connection
            connection = Connection(
                self._server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=False,
                raise_exceptions=True,
            )
        else:
            # Anonymous connection
            connection = Connection(
                self._server, auto_bind=False, raise_exceptions=True
            )

        # T4.1: negotiate StartTLS BEFORE the caller invokes .bind().
        # LDAPS (use_ssl=true) already has TLS from socket dial time —
        # no upgrade needed. Plaintext (use_tls=false and use_ssl=false)
        # is only reachable if the operator opted in via
        # allow_insecure=true; the validator refuses it otherwise.
        if self.use_tls and not self.use_ssl:
            if not connection.start_tls():
                raise ProviderConnectionException(
                    "LDAP StartTLS upgrade failed. "
                    f"Server: {self.host}:{self.port}. Refusing to "
                    "bind credentials over an unencrypted channel."
                )

        return connection

    def _authenticate_user(self, user_dn: str, password: str) -> bool:
        """
        Authenticate user by attempting to bind with their credentials

        Args:
            user_dn: User distinguished name
            password: User password

        Returns:
            True if authentication successful
        """
        try:
            connection = self._get_connection(user_dn, password)

            if connection.bind():
                connection.unbind()
                return True
            else:
                logger.debug(f"LDAP bind failed for {user_dn}: {connection.result}")
                return False

        except LDAPBindError:
            return False
        except Exception as e:
            logger.error(f"LDAP authentication error for {user_dn}: {e}")
            return False

    def _search_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Search for user in LDAP directory

        Args:
            username: Username to search for

        Returns:
            Dictionary with user information or None if not found
        """
        try:
            connection = self._get_connection()

            if not connection.bind():
                raise LDAPException(
                    f"Failed to bind for user search: {connection.result}"
                )

            # Build search filter
            search_filter = self.user_search_filter.format(username=username)

            # Determine attributes to retrieve
            attributes = [
                self.username_attr,
                self.email_attr,
                self.full_name_attr,
                self.first_name_attr,
                self.last_name_attr,
                self.groups_attr,
            ]

            # Remove duplicates and None values
            attributes = list(set(attr for attr in attributes if attr))

            # Perform search
            success = connection.search(
                search_base=self.user_base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
            )

            if not success or not connection.entries:
                connection.unbind()
                return None

            # Get first entry
            entry = connection.entries[0]
            user_info = {
                "dn": entry.entry_dn,
                "username": self._get_attribute_value(entry, self.username_attr),
                "email": self._get_attribute_value(entry, self.email_attr),
                "full_name": self._get_attribute_value(entry, self.full_name_attr),
                "first_name": self._get_attribute_value(entry, self.first_name_attr),
                "last_name": self._get_attribute_value(entry, self.last_name_attr),
                "groups": self._get_attribute_values(entry, self.groups_attr),
            }

            connection.unbind()

            # Determine role from groups
            logger.debug(
                f"LDAP user {username} retrieved groups: {user_info['groups']}"
            )
            user_info["role"] = self._determine_role_from_groups(user_info["groups"])
            logger.debug(
                f"LDAP user {username} assigned role: {user_info['role']} ({user_info['role'].value})"
            )

            return user_info

        except Exception as e:
            logger.error(f"LDAP user search error for {username}: {e}")
            return None

    def _get_attribute_value(self, entry, attribute: str) -> Optional[str]:
        """Get single attribute value from LDAP entry"""
        if not attribute or not hasattr(entry, attribute):
            return None

        value = getattr(entry, attribute)

        if value and len(value) > 0:
            return str(value[0])

        return None

    def _get_attribute_values(self, entry, attribute: str) -> List[str]:
        """Get multiple attribute values from LDAP entry"""
        if not attribute or not hasattr(entry, attribute):
            return []

        values = getattr(entry, attribute)

        if values:
            return [str(value) for value in values]

        return []

    def _determine_role_from_groups(self, groups: List[str]) -> UserRole:
        """
        Determine user role based on group memberships

        Args:
            groups: List of group DNs or names

        Returns:
            UserRole for the user
        """
        logger.debug(f"LDAP role determination - Input groups: {groups}")
        logger.debug(f"LDAP role determination - Group mappings: {self.group_mappings}")
        logger.debug(f"LDAP role determination - Default role: {self.default_role}")

        if not groups:
            logger.debug(
                "LDAP role determination - No groups found, using default role"
            )
            return self.default_role

        # Check group mappings
        for group in groups:
            logger.debug(f"LDAP role determination - Checking group: {group}")

            # Try exact match first
            if group in self.group_mappings:
                try:
                    role = UserRole(self.group_mappings[group])
                    logger.debug(
                        f"LDAP role determination - EXACT MATCH: {group} -> {role} ({role.value})"
                    )
                    return role
                except ValueError:
                    logger.warning(
                        f"Invalid role mapping for group {group}: {self.group_mappings[group]}"
                    )
                    continue

            # Try substring match (for group names within DNs)
            for mapped_group, role in self.group_mappings.items():
                if mapped_group.lower() in group.lower():
                    try:
                        role_obj = UserRole(role)
                        logger.debug(
                            f"LDAP role determination - SUBSTRING MATCH: {mapped_group} in {group} -> {role_obj} ({role_obj.value})"
                        )
                        return role_obj
                    except ValueError:
                        logger.warning(
                            f"Invalid role mapping for group {mapped_group}: {role}"
                        )
                        continue

        logger.info(
            f"LDAP role determination - No matches found, using default role: {self.default_role}"
        )
        return self.default_role

    def _create_or_update_user(self, username: str, user_info: Dict[str, Any]) -> User:
        """
        Create or update user from LDAP information

        Args:
            username: Username
            user_info: User information from LDAP

        Returns:
            User instance
        """
        from database import db

        # Check if user already exists
        user = User.query.filter_by(
            username=username, auth_provider=AuthProvider.LDAP
        ).first()

        if user:
            # Update existing user
            if self.update_user_info:
                user.email = user_info.get("email")
                user.full_name = user_info.get("full_name")
                user.role = user_info.get("role", self.default_role)
                user.update_from_provider(user_info)

            logger.info(f"Updated existing LDAP user: {username}")
        else:
            # Create new user
            user = User.create_external_user(
                username=username,
                provider=AuthProvider.LDAP,
                provider_user_id=user_info.get("dn", username),
                provider_data=user_info,
                role=user_info.get("role", self.default_role),
            )

            # Set additional fields
            user.email = user_info.get("email")
            user.full_name = user_info.get("full_name")

            db.session.add(user)
            logger.info(f"Created new LDAP user: {username}")

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise AuthenticationException(
                f"Failed to save LDAP user {username}",
                AuthenticationResult.PROVIDER_ERROR,
                {"error": str(e)},
            )

        return user

    def supports_feature(self, feature: str) -> bool:
        """
        Check if LDAP provider supports a specific feature

        Args:
            feature: Feature name to check

        Returns:
            True if feature is supported
        """
        ldap_features = [
            "authentication",
            "user_info",
            "session_management",
            "health_check",
            "group_mapping",
            "role_mapping",
            "user_sync",
        ]

        return feature in ldap_features

    def get_ldap_stats(self) -> Dict[str, Any]:
        """
        Get LDAP-specific statistics

        Returns:
            Dictionary with LDAP statistics
        """
        try:
            from database import db

            total_users = User.query.filter_by(auth_provider=AuthProvider.LDAP).count()

            # Users by role
            users_by_role = {}
            for role in UserRole:
                count = User.query.filter_by(
                    auth_provider=AuthProvider.LDAP, role=role
                ).count()
                users_by_role[role.value] = count

            return {
                "total_users": total_users,
                "users_by_role": users_by_role,
                "server": f"{self.host}:{self.port}",
                "ssl_enabled": self.use_ssl,
                "auto_create_users": self.auto_create_users,
                "group_mappings_count": len(self.group_mappings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get LDAP stats: {e}")
            return {"error": str(e)}
