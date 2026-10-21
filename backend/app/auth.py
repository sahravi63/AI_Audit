"""OIDC access-token validation and tenant authorization."""

from __future__ import annotations

import json
import ipaddress
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

import jwt
from fastapi import Depends, Header, HTTPException
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientConnectionError, PyJWKClientError, PyJWTError

from . import db


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    tenant_name: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    tenant_claim: str
    client_id: str
    redirect_uri: str


def settings() -> OIDCSettings:
    return OIDCSettings(
        issuer=os.getenv("OIDC_ISSUER", "https://identity.example.com/").strip(),
        audience=os.getenv("OIDC_AUDIENCE", "auditdex-api").strip(),
        tenant_claim=os.getenv("OIDC_TENANT_CLAIM", "tenant_id").strip(),
        client_id=os.getenv("OIDC_CLIENT_ID", "auditdex-spa").strip(),
        redirect_uri=os.getenv("OIDC_REDIRECT_URI", "http://127.0.0.1:8017/").strip(),
    )


def _is_secure_or_loopback(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return True
    if parsed.scheme != "http" or not parsed.hostname:
        return False
    if parsed.hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def _discovery_url(issuer: str) -> str:
    override = os.getenv("OIDC_DISCOVERY_URL", "").strip()
    if override:
        return override
    if not _is_secure_or_loopback(issuer):
        raise HTTPException(503, "OIDC issuer must use HTTPS, except for localhost development")
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


@lru_cache(maxsize=4)
def _discovery(issuer: str) -> dict:
    request = urllib.request.Request(
        _discovery_url(issuer),
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            metadata = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "OIDC provider discovery is unavailable") from exc

    if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
        raise HTTPException(503, "OIDC discovery issuer does not match configuration")
    jwks_uri = os.getenv("OIDC_JWKS_URI", "").strip() or metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str) or (not os.getenv("OIDC_JWKS_URI") and not _is_secure_or_loopback(jwks_uri)):
        raise HTTPException(503, "OIDC provider has no valid secure JWKS endpoint")
    metadata["jwks_uri"] = jwks_uri
    return metadata


@lru_cache(maxsize=4)
def _jwks_client(issuer: str) -> PyJWKClient:
    return PyJWKClient(_discovery(issuer)["jwks_uri"], timeout=5)


def signing_key_for_token(token: str):
    issuer = settings().issuer
    try:
        return _jwks_client(issuer).get_signing_key_from_jwt(token).key
    except PyJWKClientConnectionError as exc:
        raise HTTPException(503, "OIDC signing keys are unavailable") from exc
    except PyJWKClientError as exc:
        raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc


def authenticate_token(token: str) -> Principal:
    if len(token) > 16_384:
        raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"})

    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in ("RS256", "ES256"):
            raise InvalidTokenError("Unsupported signing algorithm")
    except PyJWTError as exc:
        raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc

    config = settings()
    try:
        claims = jwt.decode(
            token,
            signing_key_for_token(token),
            algorithms=["RS256", "ES256"],
            audience=config.audience,
            issuer=config.issuer,
            options={"require": ["exp", "iss", "aud"]},
        )
    except PyJWTError as exc:
        raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc

    tenant_id = claims.get(config.tenant_claim)
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(403, "Token has no authorized tenant")

    conn = db.connect()
    try:
        tenant_row = conn.execute("SELECT name FROM tenants WHERE id=?", (tenant_id,)).fetchone()
    finally:
        conn.close()
    if not tenant_row:
        raise HTTPException(403, "Token tenant is not registered")

    raw_scopes = claims.get("scope", claims.get("scp", []))
    if isinstance(raw_scopes, str):
        scopes = set(raw_scopes.split())
    elif isinstance(raw_scopes, list) and all(isinstance(scope, str) for scope in raw_scopes):
        scopes = set(raw_scopes)
    else:
        scopes = set()
    return Principal(tenant_id=tenant_id, tenant_name=tenant_row["name"], scopes=frozenset(scopes))


def authenticated_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization:
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    return authenticate_token(token.strip())


def authenticated_tenant(principal: Principal = Depends(authenticated_principal)) -> str:
    return principal.tenant_id


def require_scope(scope: str):
    def dependency(principal: Principal = Depends(authenticated_principal)) -> str:
        if scope not in principal.scopes:
            raise HTTPException(403, f"Required scope: {scope}")
        return principal.tenant_id

    return dependency


def public_config() -> dict[str, str]:
    config = settings()
    return {
        "issuer": config.issuer,
        "audience": config.audience,
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
    }
