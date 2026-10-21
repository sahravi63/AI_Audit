"""Provision a local-only Keycloak SPA, tenant scopes, and demo user."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.getenv("OIDC_REALM", "master")
ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "local-only-change-me")
CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "your-local-spa-client-name")
REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "http://127.0.0.1:8017/")
DEMO_USERNAME = os.getenv("KEYCLOAK_DEMO_USERNAME", "auditdex-demo")
DEMO_PASSWORD = os.getenv("KEYCLOAK_DEMO_PASSWORD", "AuditDexLocal!2026")
DEMO_TENANT = os.getenv("OIDC_DEMO_TENANT", "acme")


def request(method: str, path: str, token: str | None = None, body: dict | None = None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            contents = response.read()
            return response.status, json.loads(contents) if contents else None
    except urllib.error.HTTPError as exc:
        contents = exc.read().decode(errors="replace")
        raise RuntimeError(f"Keycloak {method} {path} returned {exc.code}: {contents}") from exc


def ensure_resource(token: str, path: str, items_path: str, name: str, spec: dict) -> dict:
    _, resources = request("GET", items_path, token)
    existing = next((item for item in resources if item.get("name") == name), None)
    if existing:
        request("PUT", f"{path}/{existing['id']}", token, spec)
        return existing
    request("POST", path, token, spec)
    _, resources = request("GET", items_path, token)
    return next(item for item in resources if item.get("name") == name)


def main() -> None:
    token_url = f"{BASE_URL}/realms/{REALM}/protocol/openid-connect/token"
    encoded = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
    }).encode()
    req = urllib.request.Request(
        token_url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            admin_token = json.loads(response.read())["access_token"]
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Cannot reach Keycloak admin token endpoint. Start Docker and run "
            "'docker compose up -d --wait' first."
        ) from exc

    realm_path = f"/admin/realms/{REALM}"
    _, clients = request("GET", f"{realm_path}/clients?clientId={urllib.parse.quote(CLIENT_ID)}", admin_token)
    client_spec = {
        "clientId": CLIENT_ID,
        "name": "AuditDex local dashboard",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [REDIRECT_URI],
        "webOrigins": [urllib.parse.urlsplit(REDIRECT_URI).scheme + "://" + urllib.parse.urlsplit(REDIRECT_URI).netloc],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": REDIRECT_URI,
        },
    }
    if clients:
        request("PUT", f"{realm_path}/clients/{clients[0]['id']}", admin_token, client_spec)
        client_uuid = clients[0]["id"]
    else:
        request("POST", f"{realm_path}/clients", admin_token, client_spec)
        _, clients = request("GET", f"{realm_path}/clients?clientId={urllib.parse.quote(CLIENT_ID)}", admin_token)
        client_uuid = next(item["id"] for item in clients if item["clientId"] == CLIENT_ID)

    scopes_path = f"{realm_path}/client-scopes"
    claims_scope = ensure_resource(
        admin_token, scopes_path, scopes_path, "auditdex-tenant",
        {
            "name": "auditdex-tenant",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        },
    )
    _, mappers = request("GET", f"{scopes_path}/{claims_scope['id']}/protocol-mappers/models", admin_token)
    mapper_specs = [
        {
            "name": "AuditDex tenant claim",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {
                "claim.name": "tenant_id",
                "claim.value": DEMO_TENANT,
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
            },
        },
        {
            "name": "AuditDex API audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": os.getenv("OIDC_AUDIENCE", "auditdex-api"),
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        },
    ]
    for mapper in mapper_specs:
        existing = next((item for item in mappers if item.get("name") == mapper["name"]), None)
        if existing:
            request(
                "DELETE",
                f"{scopes_path}/{claims_scope['id']}/protocol-mappers/models/{existing['id']}",
                admin_token,
            )
        request("POST", f"{scopes_path}/{claims_scope['id']}/protocol-mappers/models", admin_token, mapper)

    scope_ids = [claims_scope["id"]]
    for scope_name in ("auditdex:write", "auditdex:gateway"):
        scope = ensure_resource(
            admin_token, scopes_path, scopes_path, scope_name,
            {
                "name": scope_name,
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "false",
                },
            },
        )
        scope_ids.append(scope["id"])

    _, default_scopes = request("GET", f"{realm_path}/clients/{client_uuid}/default-client-scopes", admin_token)
    for scope_id in scope_ids:
        if not any(scope.get("id") == scope_id for scope in default_scopes):
            request("PUT", f"{realm_path}/clients/{client_uuid}/default-client-scopes/{scope_id}", admin_token)

    _, users = request(
        "GET",
        f"{realm_path}/users?username={urllib.parse.quote(DEMO_USERNAME)}&exact=true",
        admin_token,
    )
    user_spec = {
        "username": DEMO_USERNAME,
        "enabled": True,
        "emailVerified": True,
        "email": f"{DEMO_USERNAME}@localhost.invalid",
    }
    if users:
        user_id = users[0]["id"]
        request("PUT", f"{realm_path}/users/{user_id}", admin_token, user_spec)
    else:
        request("POST", f"{realm_path}/users", admin_token, user_spec)
        _, users = request(
            "GET",
            f"{realm_path}/users?username={urllib.parse.quote(DEMO_USERNAME)}&exact=true",
            admin_token,
        )
        user_id = next(user["id"] for user in users if user["username"] == DEMO_USERNAME)
    request(
        "PUT",
        f"{realm_path}/users/{user_id}/reset-password",
        admin_token,
        {"type": "password", "value": DEMO_PASSWORD, "temporary": False},
    )

    print("Keycloak local OIDC is configured.")
    print(f"Issuer:       {BASE_URL}/realms/{REALM}")
    print(f"Client ID:    {CLIENT_ID}")
    print(f"Redirect URI: {REDIRECT_URI}")
    print(f"Demo user:    {DEMO_USERNAME}")
    print(f"Demo password:{DEMO_PASSWORD}")
    print(f"Tenant claim: {DEMO_TENANT}")
    print("Scopes:       auditdex:write auditdex:gateway")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, urllib.error.URLError, StopIteration) as exc:
        print(f"Keycloak setup failed: {exc}", file=sys.stderr)
        sys.exit(1)
