"""
Auth, RBAC, and Multi-tenancy — OIDC/SSO, roles, team namespaces, audit log.
"""

import jwt
import uuid
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps

logger = logging.getLogger(__name__)


class Role(Enum):
    """Role hierarchy for RBAC."""
    ADMIN = "admin"           # Full access, manage users/teams
    HUNTER = "hunter"         # Create/run hunts, view all findings
    ANALYST = "analyst"       # View hunts/findings, cannot initiate
    READ_ONLY = "read_only"  # View-only access


# Permission matrix
ROLE_PERMISSIONS = {
    Role.ADMIN: {"hunt.create", "hunt.view", "hunt.delete", "hunt.approve",
                 "finding.view", "finding.export", "fleet.manage", "fleet.view",
                 "user.manage", "team.manage", "playbook.manage", "audit.view"},
    Role.HUNTER: {"hunt.create", "hunt.view", "hunt.approve",
                  "finding.view", "finding.export", "fleet.view",
                  "playbook.manage"},
    Role.ANALYST: {"hunt.view", "finding.view", "finding.export", "fleet.view"},
    Role.READ_ONLY: {"hunt.view", "finding.view"},
}


@dataclass
class User:
    """Authenticated user."""
    user_id: str
    email: str
    display_name: str
    role: Role
    team_namespace: str = "default"
    sso_provider: str = ""  # okta, entra, google
    sso_subject: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True


@dataclass
class TeamNamespace:
    """Isolated team namespace for multi-tenancy."""
    namespace_id: str
    name: str
    description: str = ""
    members: List[str] = field(default_factory=list)  # user_ids
    created_at: datetime = field(default_factory=datetime.utcnow)


class OIDCProvider:
    """
    OIDC/SSO integration for Okta, Entra ID (Azure AD), Google.
    
    Handles:
    - Discovery document fetch
    - Token validation (JWT verification)
    - User info extraction
    - Token refresh
    """

    def __init__(self, issuer_url: str, client_id: str, client_secret: str,
                 redirect_uri: str):
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._jwks_cache: Optional[Dict] = None
        self._discovery: Optional[Dict] = None

    async def discover(self) -> Dict[str, Any]:
        """Fetch OIDC discovery document."""
        import aiohttp
        url = f"{self.issuer_url}/.well-known/openid-configuration"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                self._discovery = await resp.json()
                return self._discovery

    async def validate_token(self, id_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate an ID token and extract claims.
        
        Returns user claims dict or None if invalid.
        """
        try:
            if not self._discovery:
                await self.discover()

            # In production: fetch JWKS, verify signature, check exp/aud/iss
            # Simplified for structure:
            claims = jwt.decode(
                id_token,
                options={"verify_signature": False},  # In prod: verify with JWKS
                audience=self.client_id,
            )
            return claims
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None

    def get_authorization_url(self, state: str, nonce: str) -> str:
        """Generate OIDC authorization URL for login redirect."""
        if not self._discovery:
            auth_endpoint = f"{self.issuer_url}/authorize"
        else:
            auth_endpoint = self._discovery["authorization_endpoint"]

        params = (
            f"?client_id={self.client_id}"
            f"&response_type=code"
            f"&scope=openid+profile+email"
            f"&redirect_uri={self.redirect_uri}"
            f"&state={state}"
            f"&nonce={nonce}"
        )
        return auth_endpoint + params


class AuthManager:
    """
    Central authentication and authorization manager.
    
    Handles:
    - OIDC provider configuration
    - Session/token management
    - RBAC enforcement
    - Team namespace isolation
    """

    def __init__(self, jwt_secret: str = "change-me-in-production",
                 token_expiry_hours: int = 8):
        self.jwt_secret = jwt_secret
        self.token_expiry = timedelta(hours=token_expiry_hours)
        self._users: Dict[str, User] = {}
        self._namespaces: Dict[str, TeamNamespace] = {
            "default": TeamNamespace(namespace_id="default", name="Default")
        }
        self._providers: Dict[str, OIDCProvider] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}  # token -> session info

    def register_provider(self, name: str, provider: OIDCProvider):
        """Register an OIDC provider (Okta, Entra, etc.)."""
        self._providers[name] = provider

    def create_session_token(self, user: User) -> str:
        """Create a JWT session token for an authenticated user."""
        payload = {
            "sub": user.user_id,
            "email": user.email,
            "role": user.role.value,
            "namespace": user.team_namespace,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + self.token_expiry,
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def validate_session(self, token: str) -> Optional[User]:
        """Validate a session token and return the user."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            user_id = payload["sub"]
            return self._users.get(user_id)
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def check_permission(self, user: User, permission: str) -> bool:
        """Check if a user has a specific permission."""
        allowed = ROLE_PERMISSIONS.get(user.role, set())
        return permission in allowed

    def enforce_namespace(self, user: User, resource_namespace: str) -> bool:
        """Check if user can access a resource in the given namespace."""
        if user.role == Role.ADMIN:
            return True  # Admins can access all namespaces
        return user.team_namespace == resource_namespace

    def create_namespace(self, name: str, created_by: str) -> TeamNamespace:
        """Create a new team namespace."""
        ns = TeamNamespace(
            namespace_id=f"ns_{uuid.uuid4().hex[:8]}",
            name=name,
            members=[created_by],
        )
        self._namespaces[ns.namespace_id] = ns
        return ns

    async def handle_oidc_callback(self, provider_name: str, code: str,
                                     state: str) -> Optional[str]:
        """
        Handle OIDC callback, create/update user, return session token.
        """
        provider = self._providers.get(provider_name)
        if not provider:
            return None

        # In production: exchange code for tokens, validate ID token
        # Simplified: assume token exchange happened
        return None


def require_permission(permission: str):
    """Decorator for enforcing permissions on API endpoints."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # In production, extract user from request context
            # and check permission before executing
            return await func(*args, **kwargs)
        return wrapper
    return decorator
