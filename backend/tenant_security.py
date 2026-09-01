"""Authentication and tenant-scoped connector helpers for CloudGuard.

This module deliberately keeps browser identities and connector identities
separate. Browser requests use short-lived Keycloak access tokens; connectors
use a per-tenant bearer credential configured outside source control.
"""

from __future__ import annotations

import hmac
import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping, Optional

import jwt
from fastapi import HTTPException, Request
from jwt import PyJWKClient


TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


@dataclass(frozen=True)
class RequestIdentity:
    user_id: str
    tenant_id: str
    email: str


@dataclass(frozen=True)
class ConnectorIdentity:
    connector_id: str
    tenant_id: str
    user_id: str
    scopes: frozenset[str]


def cloudguard_auth_required() -> bool:
    """Return whether browser/API requests must carry a Keycloak JWT."""
    return os.getenv("CLOUDGUARD_AUTH_REQUIRED", "false").lower() == "true"


def _require_valid_tenant_id(value: object, label: str = "tenant_id") -> str:
    if not isinstance(value, str) or not TENANT_ID_PATTERN.fullmatch(value):
        raise HTTPException(status_code=401, detail=f"A valid {label} claim is required")
    return value


def _bearer_token(headers: Mapping[str, str]) -> Optional[str]:
    authorization = headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url, cache_keys=True, lifespan=600)


def _keycloak_settings() -> tuple[str, str, str]:
    issuer = os.getenv("KEYCLOAK_ISSUER", "").rstrip("/")
    audience = os.getenv("KEYCLOAK_AUDIENCE", "").strip()
    jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "").strip()
    if not issuer or not audience or not jwks_url:
        raise RuntimeError(
            "KEYCLOAK_ISSUER, KEYCLOAK_AUDIENCE, and KEYCLOAK_JWKS_URL are required when CLOUDGUARD_AUTH_REQUIRED=true"
        )
    return issuer, audience, jwks_url


def verify_keycloak_request(request: Request) -> RequestIdentity:
    """Verify a Keycloak access token and return its server-trusted identity."""
    token = _bearer_token(request.headers)
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token required")

    try:
        issuer, audience, jwks_url = _keycloak_settings()
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token") from exc

    user_id = claims.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Token subject is required")
    tenant_id = _require_valid_tenant_id(claims.get("organization_id"), "organization_id")
    email = claims.get("email") or claims.get("preferred_username") or ""
    return RequestIdentity(user_id=user_id, tenant_id=tenant_id, email=str(email))


def request_identity(request: Request) -> Optional[RequestIdentity]:
    """Get a previously-verified identity, verifying it when required."""
    existing = getattr(request.state, "identity", None)
    if isinstance(existing, RequestIdentity):
        return existing
    if not cloudguard_auth_required():
        return None
    identity = verify_keycloak_request(request)
    request.state.identity = identity
    return identity


def require_request_identity(request: Request) -> RequestIdentity:
    identity = request_identity(request)
    if not identity:
        raise HTTPException(status_code=401, detail="Authentication is required")
    return identity


def parse_connector_credentials(raw: Optional[str] = None) -> dict[str, tuple[ConnectorIdentity, str]]:
    """Read connector credentials without logging or returning their tokens.

    CONNECTOR_CREDENTIALS_JSON format:
    {
      "connector-id": {
        "token": "secret managed by Dokploy",
        "tenant_id": "tenant UUID or slug",
        "user_id": "CloudGuard owner ID",
        "scopes": ["evidence:write", "grc:read"]
      }
    }
    """
    raw = raw if raw is not None else os.getenv("CONNECTOR_CREDENTIALS_JSON")
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("CONNECTOR_CREDENTIALS_JSON must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("CONNECTOR_CREDENTIALS_JSON must be an object keyed by connector ID")

    parsed: dict[str, tuple[ConnectorIdentity, str]] = {}
    for connector_id, config in decoded.items():
        if not isinstance(connector_id, str) or not connector_id or not isinstance(config, dict):
            raise RuntimeError("Each connector credential requires a non-empty ID and object value")
        token = config.get("token")
        user_id = config.get("user_id")
        scopes = config.get("scopes")
        if not isinstance(token, str) or len(token) < 32:
            raise RuntimeError(f"Connector {connector_id} must use a token of at least 32 characters")
        if not isinstance(user_id, str) or not user_id:
            raise RuntimeError(f"Connector {connector_id} requires a user_id")
        if not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) for scope in scopes):
            raise RuntimeError(f"Connector {connector_id} requires one or more scopes")
        identity = ConnectorIdentity(
            connector_id=connector_id,
            tenant_id=_require_valid_tenant_id(config.get("tenant_id")),
            user_id=user_id,
            scopes=frozenset(scopes),
        )
        parsed[connector_id] = (identity, token)
    return parsed


def require_connector_identity(request: Request, required_scope: str) -> ConnectorIdentity:
    """Authenticate a connector and derive tenant/user solely from its secret."""
    connector_id = request.headers.get("x-connector-id", "")
    token = _bearer_token(request.headers)
    if not connector_id or not token:
        raise HTTPException(status_code=401, detail="Connector bearer token and ID are required")

    configured = parse_connector_credentials().get(connector_id)
    if not configured:
        raise HTTPException(status_code=401, detail="Unknown connector")
    identity, expected_token = configured
    if not hmac.compare_digest(token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid connector credential")
    if required_scope not in identity.scopes:
        raise HTTPException(status_code=403, detail="Connector is not authorized for this operation")
    return identity
