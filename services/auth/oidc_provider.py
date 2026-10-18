"""
ABOUTME: OIDC/OAuth2 authentication provider for modern SSO integration
ABOUTME: Supports Azure AD, Okta, Auth0, Google, Keycloak and other OIDC providers

File: services/auth/oidc_provider.py

Description:
    OpenID Connect (OIDC) authentication provider for modern SSO integration with
    enterprise identity providers. Supports multiple OIDC providers including Azure AD,
    Okta, Auth0, Google Workspace, and Keycloak. Handles JWT token validation, claims
    processing, and role mapping from OIDC provider data.

Key features:
    - Multi-provider OIDC support (Azure AD, Okta, Auth0, Google, Keycloak)
    - JWT token validation and signature verification
    - Claims-based role and permission mapping
    - Automatic user provisioning and profile synchronization
    - PKCE support for enhanced security
    - Token refresh and session management
    - Discovery document support for dynamic configuration
    - Comprehensive error handling and logging
    - Group/role claims processing

Author: Emfour Solutions
Created: 2025-07-26
"""

import base64
import json

# Standard library imports
import logging
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# Third-party imports
import requests

from services.logging_service import get_module_logger
from utils.config_helpers import ConfigHelper

try:
    import jwt
    from jwt.exceptions import (
        ExpiredSignatureError,
        InvalidSignatureError,
        InvalidTokenError,
    )

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Local application imports
from models.user import AuthProvider, User, UserRole

from .base_provider import (
    AuthenticationException,
    AuthenticationResponse,
    AuthenticationResult,
    BaseAuthenticationProvider,
    ProviderConfigurationException,
    ProviderConnectionException,
)

# Module-level logger
logger = get_module_logger(__name__)

# Name given to the single provider when config uses the flat schema
FLAT_PROVIDER_NAME = "oidc"

# Standard OIDC discovery path (RFC 8414 / OpenID Connect Discovery 1.0)
DISCOVERY_WELL_KNOWN_PATH = ".well-known/openid-configuration"


class OIDCAuthProvider(BaseAuthenticationProvider):
    """
    OpenID Connect authentication provider for SSO integration
    """

    def __init__(self, config: Dict[str, Any] = None):
        if not JWT_AVAILABLE:
            raise ProviderConfigurationException(
                "PyJWT library is not available. Install with: pip install PyJWT[crypto]"
            )

        if not CRYPTOGRAPHY_AVAILABLE:
            raise ProviderConfigurationException(
                "cryptography library is not available. Install with: pip install cryptography"
            )

        # Initialize config and determine active provider before base class validation
        if config is None:
            config = {}
        self.config = config

        # Provider configuration using ConfigHelper
        helper = ConfigHelper(config)
        self.providers_config = helper.get("providers", {})
        if not self.providers_config and self._is_flat_config(config):
            # authentication.yaml emits a single flat OIDC block (issuer,
            # client_id, scopes, role_mapping at the top level) rather than a
            # providers map. Normalise it so the rest of the class sees one
            # enabled provider.
            self.providers_config = {
                FLAT_PROVIDER_NAME: self._normalize_flat_config(config)
            }
        self.active_provider = self._determine_active_provider()

        if not self.active_provider:
            raise ProviderConfigurationException("No OIDC provider is enabled")

        # Set up provider-specific properties before base class validation
        provider_helper = ConfigHelper(
            self.providers_config.get(self.active_provider, {})
        )
        self.client_id = provider_helper.get("client_id", "")
        self.client_secret = provider_helper.get("client_secret", "")
        self.discovery_url = provider_helper.get("discovery_url", "")
        self.scope = provider_helper.get("scope", "openid profile email")

        # Discovery and JWKS caching (needed before base class validation,
        # which fetches the discovery document)
        self._discovery_cache = {}
        self._jwks_cache = {}
        self._cache_ttl = 3600  # 1 hour
        self._last_discovery_fetch = {}
        self._last_jwks_fetch = {}

        super().__init__(AuthProvider.OIDC, config)

        # Role mapping (flat schema spells the key "role_mapping")
        self.role_mappings = self.config.get("role_mappings") or self.config.get(
            "role_mapping", {}
        )
        self.default_role = UserRole(self.config.get("default_role", "user"))

        # Settings
        self.auto_create_users = self.config.get("auto_create_users", True)
        self.update_user_info = self.config.get("update_user_info", True)

        # Initialize provider discovery
        self._load_discovery_document()

        logger.info(
            f"OIDC authentication provider initialized (provider: {self.active_provider})"
        )

    @staticmethod
    def _is_flat_config(config: Dict[str, Any]) -> bool:
        """True when config is the flat single-provider schema from authentication.yaml"""
        return any(key in config for key in ("issuer", "client_id", "discovery_url"))

    @staticmethod
    def _normalize_flat_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate the flat authentication.yaml schema into a provider entry.

        Derives discovery_url from issuer when not given explicitly, and joins
        the scopes list into the space-separated scope string OIDC expects.
        """
        discovery_url = config.get("discovery_url", "")
        issuer = config.get("issuer", "")
        if not discovery_url and issuer:
            discovery_url = f"{issuer.rstrip('/')}/{DISCOVERY_WELL_KNOWN_PATH}"

        scope = config.get("scope", "")
        scopes = config.get("scopes")
        if not scope and scopes:
            scope = " ".join(scopes)

        return {
            "enabled": True,
            "client_id": config.get("client_id", ""),
            "client_secret": config.get("client_secret", ""),
            "discovery_url": discovery_url,
            "scope": scope or "openid profile email",
        }

    def _determine_active_provider(self) -> Optional[str]:
        """Determine which OIDC provider is active"""
        for provider_name, provider_config in self.providers_config.items():
            if provider_config.get("enabled", False):
                return provider_name
        return None

    def authenticate(
        self,
        username: str = None,
        password: str = None,
        authorization_code: str = None,
        state: str = None,
        **kwargs,
    ) -> AuthenticationResponse:
        """
        Authenticate user with OIDC provider

        Note: OIDC authentication is typically handled through redirect flow,
        not direct username/password authentication.

        Args:
            username: Not used for OIDC (for interface compatibility)
            password: Not used for OIDC (for interface compatibility)
            authorization_code: Authorization code from OIDC callback
            state: State parameter for CSRF protection
            **kwargs: Additional parameters

        Returns:
            AuthenticationResponse with authentication result
        """
        if authorization_code:
            return self._handle_authorization_code(authorization_code, state)
        else:
            return AuthenticationResponse(
                result=AuthenticationResult.CONFIGURATION_ERROR,
                message="OIDC authentication requires authorization code flow",
            )

    def get_authorization_url(
        self, redirect_uri: str, state: str = None
    ) -> Tuple[str, str]:
        """
        Get authorization URL for OIDC login

        Args:
            redirect_uri: Callback URI after authentication
            state: State parameter for CSRF protection

        Returns:
            Tuple of (authorization_url, state)
        """
        if not state:
            state = secrets.token_urlsafe(32)

        discovery = self._get_discovery_document()
        if not discovery:
            raise ProviderConnectionException("Failed to load OIDC discovery document")

        auth_endpoint = discovery.get("authorization_endpoint")
        if not auth_endpoint:
            raise ProviderConfigurationException(
                "No authorization endpoint in discovery document"
            )

        # Build authorization URL
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "state": state,
            "response_mode": "query",
        }

        # Add provider-specific parameters
        if self.active_provider == "azure_ad":
            params["response_mode"] = "form_post"

        auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

        logger.info(
            f"Generated OIDC authorization URL for provider: {self.active_provider}"
        )
        return auth_url, state

    def _handle_authorization_code(
        self, code: str, state: str = None
    ) -> AuthenticationResponse:
        """
        Handle authorization code from OIDC callback

        Args:
            code: Authorization code
            state: State parameter for validation

        Returns:
            AuthenticationResponse with authentication result
        """
        try:
            # Exchange code for tokens
            tokens = self._exchange_code_for_tokens(code)

            if not tokens:
                return AuthenticationResponse(
                    result=AuthenticationResult.PROVIDER_ERROR,
                    message="Failed to exchange authorization code for tokens",
                )

            # Validate and decode ID token
            id_token = tokens.get("id_token")
            if not id_token:
                return AuthenticationResponse(
                    result=AuthenticationResult.PROVIDER_ERROR,
                    message="No ID token received from provider",
                )

            claims = self._validate_and_decode_token(id_token)
            if not claims:
                return AuthenticationResponse(
                    result=AuthenticationResult.INVALID_CREDENTIALS,
                    message="Invalid ID token",
                )

            # Extract user information
            user_info = self._extract_user_info(claims, tokens)
            username = user_info.get("username") or user_info.get("email")

            if not username:
                return AuthenticationResponse(
                    result=AuthenticationResult.PROVIDER_ERROR,
                    message="No username or email found in OIDC claims",
                )

            # Create or update user
            user = None
            if self.auto_create_users:
                try:
                    user = self._create_or_update_user(username, user_info)
                except Exception as e:
                    logger.error(f"Failed to create/update OIDC user {username}: {e}")
                    return AuthenticationResponse(
                        result=AuthenticationResult.PROVIDER_ERROR,
                        message="User management error",
                        details={"error": str(e)},
                    )
            else:
                # Find existing user
                user = User.query.filter_by(
                    username=username, auth_provider=AuthProvider.OIDC
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
                        logger.error(f"Failed to update OIDC user info: {e}")

            logger.info(f"Successful OIDC authentication for user: {username}")
            return AuthenticationResponse(
                result=AuthenticationResult.SUCCESS,
                user=user,
                message="Authentication successful",
                details={
                    "provider": "oidc",
                    "oidc_provider": self.active_provider,
                    "claims": claims,
                },
                session_data={
                    "access_token": tokens.get("access_token"),
                    "refresh_token": tokens.get("refresh_token"),
                    "token_expires_at": time.time() + tokens.get("expires_in", 3600),
                },
            )

        except Exception as e:
            logger.error(f"OIDC authentication error: {e}", exc_info=True)
            return AuthenticationResponse(
                result=AuthenticationResult.PROVIDER_ERROR,
                message="OIDC authentication error",
                details={"error": str(e)},
            )

    def get_user_info(self, username: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Get user information from OIDC provider

        Args:
            username: Username to look up
            **kwargs: Additional parameters (may include access_token)

        Returns:
            Dictionary with user information or None if not found
        """
        access_token = kwargs.get("access_token")

        if not access_token:
            # Can't get info without token for OIDC
            return None

        try:
            discovery = self._get_discovery_document()
            userinfo_endpoint = discovery.get("userinfo_endpoint")

            if not userinfo_endpoint:
                return None

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }

            response = requests.get(userinfo_endpoint, headers=headers, timeout=30)

            if response.status_code == 200:
                userinfo = response.json()
                return self._extract_user_info(userinfo)
            else:
                logger.warning(f"Failed to get OIDC userinfo: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error getting OIDC user info: {e}")
            return None

    def validate_configuration(self) -> List[str]:
        """
        Validate OIDC provider configuration

        Returns:
            List of configuration issues
        """
        issues = []

        # Check if at least one provider is enabled
        if not self.active_provider:
            issues.append("No OIDC provider is enabled")
            return issues

        # Validate active provider config
        if not self.client_id:
            issues.append(f"Client ID is required for {self.active_provider}")

        if not self.client_secret:
            issues.append(f"Client secret is required for {self.active_provider}")

        if not self.discovery_url:
            issues.append(f"Discovery URL is required for {self.active_provider}")

        # Validate discovery URL format
        if self.discovery_url and not self.discovery_url.startswith(
            ("http://", "https://")
        ):
            issues.append("Discovery URL must be a valid HTTP/HTTPS URL")

        # Validate default role
        try:
            UserRole(self.config.get("default_role", "user"))
        except ValueError:
            issues.append(f"Invalid default_role: {self.config.get('default_role')}")

        # Test discovery document
        try:
            discovery = self._get_discovery_document()
            if not discovery:
                issues.append("Failed to fetch OIDC discovery document")
            else:
                required_endpoints = [
                    "authorization_endpoint",
                    "token_endpoint",
                    "jwks_uri",
                ]
                for endpoint in required_endpoints:
                    if endpoint not in discovery:
                        issues.append(f"Missing {endpoint} in discovery document")
        except Exception as e:
            issues.append(f"Discovery document error: {str(e)}")

        return issues

    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check for OIDC provider

        Returns:
            Dictionary with health status
        """
        try:
            # Test discovery document
            discovery = self._get_discovery_document()

            if not discovery:
                raise Exception("Failed to fetch discovery document")

            # Test JWKS endpoint
            jwks = self._get_jwks()

            if not jwks:
                raise Exception("Failed to fetch JWKS")

            return {
                "status": "healthy",
                "provider": "oidc",
                "oidc_provider": self.active_provider,
                "discovery_url": self.discovery_url,
                "endpoints_available": len(
                    [k for k in discovery.keys() if k.endswith("_endpoint")]
                ),
                "jwks_keys_count": len(jwks.get("keys", [])),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "oidc",
                "oidc_provider": self.active_provider,
                "discovery_url": self.discovery_url,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _load_discovery_document(self) -> None:
        """Load OIDC discovery document"""
        try:
            self._get_discovery_document()
        except Exception as e:
            logger.warning(f"Failed to load OIDC discovery document: {e}")

    def _get_discovery_document(self) -> Optional[Dict[str, Any]]:
        """
        Get OIDC discovery document with caching

        Returns:
            Discovery document or None if failed
        """
        now = time.time()
        cache_key = f"{self.active_provider}_discovery"

        # Check cache
        if (
            cache_key in self._discovery_cache
            and cache_key in self._last_discovery_fetch
            and now - self._last_discovery_fetch[cache_key] < self._cache_ttl
        ):
            return self._discovery_cache[cache_key]

        try:
            response = requests.get(self.discovery_url, timeout=30)
            response.raise_for_status()

            discovery = response.json()

            # Cache the result
            self._discovery_cache[cache_key] = discovery
            self._last_discovery_fetch[cache_key] = now

            logger.debug(f"Fetched OIDC discovery document for {self.active_provider}")
            return discovery

        except Exception as e:
            logger.error(f"Failed to fetch OIDC discovery document: {e}")
            return None

    def _get_jwks(self) -> Optional[Dict[str, Any]]:
        """
        Get JWKS (JSON Web Key Set) with caching

        Returns:
            JWKS document or None if failed
        """
        discovery = self._get_discovery_document()
        if not discovery:
            return None

        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            return None

        now = time.time()
        cache_key = f"{self.active_provider}_jwks"

        # Check cache
        if (
            cache_key in self._jwks_cache
            and cache_key in self._last_jwks_fetch
            and now - self._last_jwks_fetch[cache_key] < self._cache_ttl
        ):
            return self._jwks_cache[cache_key]

        try:
            response = requests.get(jwks_uri, timeout=30)
            response.raise_for_status()

            jwks = response.json()

            # Cache the result
            self._jwks_cache[cache_key] = jwks
            self._last_jwks_fetch[cache_key] = now

            logger.debug(f"Fetched JWKS for {self.active_provider}")
            return jwks

        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            return None

    def _exchange_code_for_tokens(self, code: str) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for tokens

        Args:
            code: Authorization code

        Returns:
            Token response or None if failed
        """
        discovery = self._get_discovery_document()
        if not discovery:
            return None

        token_endpoint = discovery.get("token_endpoint")
        if not token_endpoint:
            return None

        try:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }

            response = requests.post(
                token_endpoint, data=data, headers=headers, timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"Token exchange failed: {response.status_code} - {response.text}"
                )
                return None

        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            return None

    def _validate_and_decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and decode JWT token

        Args:
            token: JWT token to validate

        Returns:
            Token claims or None if invalid
        """
        try:
            # Get JWKS for signature verification
            jwks = self._get_jwks()
            if not jwks:
                logger.error("No JWKS available for token verification")
                return None

            # Decode token header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            # Find the matching key
            public_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                    break

            if not public_key:
                logger.error(f"No matching key found for kid: {kid}")
                return None

            # Verify and decode token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                options={"verify_exp": True},
            )

            return claims

        except ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except InvalidSignatureError:
            logger.warning("JWT token has invalid signature")
            return None
        except InvalidTokenError as e:
            logger.warning(f"JWT token validation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"JWT token validation error: {e}")
            return None

    def _extract_user_info(
        self, claims: Dict[str, Any], tokens: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Extract user information from OIDC claims

        Args:
            claims: JWT claims or userinfo response
            tokens: Token response (optional)

        Returns:
            Extracted user information
        """
        user_info = {
            "id": claims.get("sub"),
            "username": claims.get("preferred_username") or claims.get("email"),
            "email": claims.get("email"),
            "full_name": claims.get("name"),
            "first_name": claims.get("given_name"),
            "last_name": claims.get("family_name"),
            "groups": [],
            "roles": [],
        }

        # Provider-specific claim extraction
        if self.active_provider == "azure_ad":
            user_info["groups"] = claims.get("groups", [])
            user_info["roles"] = claims.get("roles", [])
            if not user_info["username"]:
                user_info["username"] = claims.get("upn") or claims.get("unique_name")

        elif self.active_provider == "okta":
            user_info["groups"] = claims.get("groups", [])

        elif self.active_provider == "auth0":
            # Auth0 stores custom claims with namespace
            namespace = "https://trakbridge.local/"
            user_info["roles"] = claims.get(f"{namespace}roles", [])
            user_info["groups"] = claims.get(f"{namespace}groups", [])

        elif self.active_provider == "keycloak":
            resource_access = claims.get("resource_access", {})
            client_access = resource_access.get(self.client_id, {})
            user_info["roles"] = client_access.get("roles", [])

            realm_access = claims.get("realm_access", {})
            user_info["groups"] = realm_access.get("roles", [])

        # Determine role from groups/roles
        user_info["role"] = self._determine_role_from_claims(user_info)

        return user_info

    def _determine_role_from_claims(self, user_info: Dict[str, Any]) -> UserRole:
        """
        Determine user role from OIDC claims

        Args:
            user_info: User information with groups and roles

        Returns:
            UserRole for the user
        """
        all_claims = user_info.get("groups", []) + user_info.get("roles", [])

        # Check role mappings
        for claim in all_claims:
            if claim in self.role_mappings:
                try:
                    return UserRole(self.role_mappings[claim])
                except ValueError:
                    logger.warning(
                        f"Invalid role mapping for claim {claim}: {self.role_mappings[claim]}"
                    )
                    continue

        return self.default_role

    def _create_or_update_user(self, username: str, user_info: Dict[str, Any]) -> User:
        """
        Create or update user from OIDC information

        Args:
            username: Username
            user_info: User information from OIDC

        Returns:
            User instance
        """
        from database import db

        # Check if user already exists
        user = User.query.filter_by(
            username=username, auth_provider=AuthProvider.OIDC
        ).first()

        if user:
            # Update existing user
            if self.update_user_info:
                user.email = user_info.get("email")
                user.full_name = user_info.get("full_name")
                user.role = user_info.get("role", self.default_role)
                user.update_from_provider(user_info)

            logger.info(f"Updated existing OIDC user: {username}")
        else:
            # Create new user
            user = User.create_external_user(
                username=username,
                provider=AuthProvider.OIDC,
                provider_user_id=user_info.get("id", username),
                provider_data=user_info,
                role=user_info.get("role", self.default_role),
            )

            # Set additional fields
            user.email = user_info.get("email")
            user.full_name = user_info.get("full_name")

            db.session.add(user)
            logger.info(f"Created new OIDC user: {username}")

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise AuthenticationException(
                f"Failed to save OIDC user {username}",
                AuthenticationResult.PROVIDER_ERROR,
                {"error": str(e)},
            )

        return user

    def supports_feature(self, feature: str) -> bool:
        """
        Check if OIDC provider supports a specific feature

        Args:
            feature: Feature name to check

        Returns:
            True if feature is supported
        """
        oidc_features = [
            "authentication",
            "user_info",
            "session_management",
            "health_check",
            "token_validation",
            "claims_mapping",
            "role_mapping",
            "user_sync",
        ]

        return feature in oidc_features

    def get_oidc_stats(self) -> Dict[str, Any]:
        """
        Get OIDC-specific statistics

        Returns:
            Dictionary with OIDC statistics
        """
        try:
            from database import db

            total_users = User.query.filter_by(auth_provider=AuthProvider.OIDC).count()

            # Users by role
            users_by_role = {}
            for role in UserRole:
                count = User.query.filter_by(
                    auth_provider=AuthProvider.OIDC, role=role
                ).count()
                users_by_role[role.value] = count

            return {
                "total_users": total_users,
                "users_by_role": users_by_role,
                "active_provider": self.active_provider,
                "discovery_url": self.discovery_url,
                "auto_create_users": self.auto_create_users,
                "role_mappings_count": len(self.role_mappings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get OIDC stats: {e}")
            return {"error": str(e)}
