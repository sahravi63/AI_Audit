# AuditDex AI

AuditDex AI is a small AI-agent governance and continuous-audit prototype. A
deterministic policy engine evaluates tool calls before the demo gateway
executes them. The API stores tenant-scoped action events, approvals, policy
versions, and hash-chained audit records. A browser dashboard displays this
evidence and supports policy and approval management.

> **Prototype, not a production security boundary.** The included tool adapter
> is simulated, the default unmatched-action policy is allow, and the local
> SQLite audit chain is not immutable storage. Review
> [Security and prototype limitations](#security-and-prototype-limitations)
> before using the project with sensitive data.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Run locally](#run-locally)
- [Configure OIDC authentication](#configure-oidc-authentication)
- [Run the gateway](#run-the-gateway)
- [API reference](#api-reference)
- [Seed data](#seed-data)
- [Tests](#tests)
- [Configuration reference](#configuration-reference)
- [Security and prototype limitations](#security-and-prototype-limitations)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)

## Features

- **Dashboard:** overview metrics, recent actions, policy coverage, incidents,
  approvals, audit integrity, and agent inventory.
- **Agent registry:** record an agent's owner, purpose, environment, tools,
  capabilities, and risk level.
- **Deterministic policy engine:** ordered, first-match-wins rules over agent,
  capability, resource, tool, environment, or API-call fields. Effects are
  `deny`, `require_approval`, and `allow`.
- **Gateway decisions:** enforced calls are executed by the demo adapter only
  when allowed. Blocked and approval-pending calls are not executed.
- **Human approval queue:** approve or reject a pending action and add a review
  note. An approval records a decision; it does not resume the original call.
- **Discovery mode:** record an observation without enforcing its policy
  result. The demo gateway executes its mock adapter in this mode.
- **Audit evidence:** events link to traces and policy versions; the audit
  endpoint provides an export and a SHA-256 hash-chain verification result.
- **Tenant isolation:** dashboard/API tenant selection comes from a verified
  access-token claim, not from a caller-controlled tenant header.

## Architecture

```text
Browser dashboard ── OIDC access token ──┐
                                         v
Agent ──> gateway client ──> FastAPI control plane ──> SQLite
             |                  |
             |                  +── OIDC discovery / JWKS validation
             +── mock tool adapter
```

- `backend/app/main.py` serves the FastAPI control plane, dashboard, API, and
  static assets.
- `backend/app/auth.py` loads OIDC discovery/JWKS metadata, verifies signed
  access tokens, checks issuer/audience/expiry, resolves the authorized tenant,
  and enforces write/gateway scopes.
- `backend/app/policy_engine.py` evaluates deterministic policies.
- `backend/app/services.py` coordinates policy evaluation, event persistence,
  approvals, and policy updates.
- `backend/app/db.py` owns SQLite connections, schema, and transactions.
- `backend/app/audit_log.py` appends and verifies the hash-chained audit log.
- `backend/app/seed.py` creates the Acme demo workspace, agents, policies, and
  sample actions.
- `gateway/gateway.py` sends an authenticated request for a policy decision,
  then invokes the mock tool adapter when appropriate.
- `web/` contains the vanilla HTML, CSS, and JavaScript dashboard.

## Requirements

- Python 3.10 or later.
- An OIDC provider configured to issue JWT access tokens for this API. The
  dashboard additionally needs an OIDC public client that supports
  Authorization Code + PKCE.
- Node.js is optional and only needed for the dashboard JavaScript syntax
  check.

The repository includes a Windows virtual environment for this workspace, but
you can use any compatible Python environment.

## Run locally

From the repository root in PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt

$env:OIDC_ISSUER = "http://localhost:8080/realms/master"
$env:OIDC_AUDIENCE = "auditdex-api"
$env:OIDC_TENANT_CLAIM = "tenant_id"
$env:OIDC_CLIENT_ID = "your-local-spa-client-name"
$env:OIDC_REDIRECT_URI = "http://127.0.0.1:8017/"

Set-Location backend
python -m app.seed
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8017
```

First, follow [Run the full project with Docker](#run-the-full-project-with-docker) to start
and configure the local identity provider. Then open
<http://127.0.0.1:8017/> and select **Sign in**. The API's interactive
documentation is at <http://127.0.0.1:8017/docs/>.

The default database is `backend/auditdex.sqlite3`. To use another SQLite
file, set `AUDITDEX_DB` to its absolute path before starting the API:

```powershell
$env:AUDITDEX_DB = "C:\data\auditdex-demo.sqlite3"
```

The seed script is safe to rerun for an already-seeded workspace; it detects
the demo agent and exits without appending actions or changing policy versions.

## Run the full project with Docker

Docker Compose starts the FastAPI dashboard/API and the development Keycloak
identity provider. The API is published on host port **8017** (container port
8000), avoiding the commonly occupied port 8000. Keycloak remains on port 8080.
The SQLite database and Keycloak settings persist in named Docker volumes.

From the repository root in PowerShell:

```powershell
docker compose up -d --build --wait
docker compose exec auditdex python /srv/scripts/setup-keycloak.py
```

Then open <http://127.0.0.1:8017/> and sign in with the local demo user below.
The first start downloads the container images and builds the API image. To
inspect startup:

```powershell
docker compose ps
docker compose logs -f auditdex keycloak
```

To stop the stack while preserving its data, run `docker compose down`. To
remove both the demo database and Keycloak configuration, run
`docker compose down -v`.

The local demo login provisioned by the script is:

```text
Username: auditdex-demo
Password: AuditDexLocal!2026
Tenant:   acme
```

These credentials and the default administrator password are for local
development only. Do not expose port 8080 to an untrusted network or reuse
these credentials in production. The browser uses `localhost` for Keycloak's
issuer URL, while its callback uses `127.0.0.1:8017`; the container uses the
Compose service address for private discovery and signing-key requests. Plain
HTTP is accepted only for this localhost development setup. Use HTTPS outside
local development.

## Configure OIDC authentication

For a Docker-based local setup, use the [Docker instructions above](#run-the-full-project-with-docker).
For an existing provider, replace the example values with that provider's
issuer, audience, public SPA client ID, and callback URL.

### Identity-provider setup

1. Register a **public single-page application (SPA)** client; do not put a
   client secret in this repository or browser.
2. Enable **Authorization Code flow with PKCE (S256)**.
3. Register the callback URL exactly as served, for example
   `http://127.0.0.1:8017/`. For a deployed HTTPS site, register its HTTPS
   origin and callback instead.
4. Allow the dashboard origin at the provider's authorization/token endpoints
   as required by the provider's CORS settings.
5. Configure an API/resource audience and issue JWT access tokens with that
   audience.
6. Include a signed string claim identifying the tenant. By default the claim
   is named `tenant_id`. Its value must match an existing row in the local
   `tenants` table.
7. Issue appropriate scopes:
   - `auditdex:write` for dashboard agent/policy changes and approval decisions.
   - `auditdex:gateway` for gateway evaluation and discovery requests.
   - Read-only API endpoints require a valid tenant token but no extra
     application scope.

### Token validation

For API requests, the server:

- requires an `Authorization: Bearer <access-token>` header;
- obtains OIDC metadata from
  `<OIDC_ISSUER>/.well-known/openid-configuration` and signing keys from the
  provider's HTTPS JWKS endpoint;
- accepts RS256 or ES256 signed JWTs, validating signature, exact issuer,
  configured audience, and expiry;
- requires the configured tenant claim to name a tenant already present in
  the database; and
- checks `auditdex:write` on mutation endpoints and `auditdex:gateway` on
  internal gateway endpoints.

The API rejects an `X-Tenant-Id` header as a tenant selector. Each gateway
request's body tenant must equal the tenant in its verified bearer token.
Provider discovery and JWKS keys are cached in-process; restart the API after
changing providers or issuer settings.

### Browser sign-in

The dashboard discovers the provider endpoints, creates PKCE/state/nonce
values, redirects to the provider, exchanges the authorization code, and keeps
the access token in tab-scoped `sessionStorage`. It sends the access token as a
bearer credential and obtains the displayed tenant from `/auth/me`. The exact
callback URL is configured with `OIDC_REDIRECT_URI`. Signing out clears the
browser's local session token.

**Important:** this is a minimal generic OIDC client, not a complete identity
SDK. It checks the returned ID-token nonce in the browser; the API does not
use that ID token for authorization and validates the access token itself.
For production, use a maintained OIDC client library and configure token
refresh, logout/session expiration, redirect URI policy, provider-specific
audience/resource parameters, and security monitoring.

### Cross-origin hosting

The dashboard and API are same-origin by default. Cross-origin requests are
disabled unless explicitly allowed. To serve the dashboard/API from a
different trusted web origin, set an exact comma-separated origin allowlist
before startup:

```powershell
$env:AUDITDEX_ALLOWED_ORIGINS = "https://audit.example.com"
```

Do not use `*` for production origins.

## Run the gateway

The gateway is a Python client of the control-plane API. It needs an
OIDC **access token** whose signed tenant claim matches the `tenant_id`
argument and whose scopes include `auditdex:gateway`.

```powershell
$env:AUDITDEX_GATEWAY_TOKEN = "<short-lived gateway access token>"
$env:AUDITDEX_CONTROL_PLANE = "http://127.0.0.1:8000"
```

`AUDITDEX_CONTROL_PLANE` is optional when the API uses its default address.
Keep tokens out of source control, logs, shell history, and screenshots. In
production, obtain short-lived gateway tokens from a workload identity
integration rather than manually copying them.

Example call, from the repository root while the API is running:

```python
from gateway.gateway import GatewayError, handle_tool_call

try:
    result = handle_tool_call(
        tenant_id="acme",
        agent_id="agt_sales",
        tool="Salesforce",
        api_call="crm.export_customers",
        args={"scope": "all"},
        user_request="Export all customers",
    )
    print(result)
except GatewayError as exc:
    print(f"Gateway failed closed: {exc}")
```

Expected behavior:

- An allowed enforced decision includes a mock result.
- A blocked decision returns `result: null`, a policy-violation error, and
  optional allowed alternatives.
- A pending-approval decision returns `result: null`; no call is made.
- Invalid mode values raise `ValueError`.
- Missing, rejected, or unavailable credentials/control plane raise
  `GatewayError`; the gateway does not invoke the adapter on those failures.

The exported function also accepts `mode="log_only"`. In that mode, the
control plane stores an `observed` event and the mock adapter executes without
policy enforcement. Do not treat discovery events as protected actions.

### CLI demo

With the API running, configure `AUDITDEX_GATEWAY_TOKEN`, then run:

```powershell
python gateway\gateway.py
```

The CLI attempts several sample calls. The `ghost_agent` scenario should fail
closed because that agent is not registered.

## API reference

All `/api/*` endpoints require a verified bearer token. Responses are scoped
to the tenant in the token's configured tenant claim; a tenant header cannot
override it. Mutation routes require `auditdex:write`. Internal gateway routes
require `auditdex:gateway` and a matching body tenant.

| Method | Path | Required access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/auth/config` | Public | Browser OIDC issuer, audience, and SPA client ID. |
| `GET` | `/auth/me` | Valid bearer token | Return the verified tenant ID and tenant name. |
| `GET` | `/api/overview` | Valid bearer token | Tenant overview metrics and recent events. |
| `GET` | `/api/agents` | Valid bearer token | List tenant agents. |
| `POST` | `/api/agents` | `auditdex:write` | Register an agent. |
| `GET` | `/api/policies` | Valid bearer token | List tenant policies. |
| `POST` | `/api/policies` | `auditdex:write` | Create or update a policy. |
| `POST` | `/api/policies/simulate` | `auditdex:write` | Replay events against an unpersisted candidate policy. |
| `GET` | `/api/actions` | Valid bearer token | List actions; supports `limit`, `agent_id`, `decision`, `trace_id`, and `q`. |
| `GET` | `/api/traces/{trace_id}` | Valid bearer token | List tenant events in a trace. |
| `GET` | `/api/approvals` | Valid bearer token | List tenant approval requests. |
| `POST` | `/api/approvals/{approval_id}/decide` | `auditdex:write` | Approve or reject a pending request. |
| `GET` | `/api/incidents` | Valid bearer token | List blocked/rejected events and trace context. |
| `GET` | `/api/audit/verify` | Valid bearer token | Verify the local audit hash chain. |
| `GET` | `/api/audit/export` | Valid bearer token | Export tenant records and chain verification. |
| `POST` | `/internal/evaluate` | `auditdex:gateway` | Evaluate and record an enforced gateway call. |
| `POST` | `/internal/observe` | `auditdex:gateway` | Record a log-only observation. |

The gateway request body for both internal endpoints includes `tenant_id`,
`agent_id`, `tool`, `api_call`, and optional `args`, `resource`, `user_request`,
`trace_id`, and `source`. A call for an unregistered agent is rejected
fail-closed.

### Create a policy

Policy JSON requires a name, effect, match field, and non-empty match pattern.
Optional values include `id`, `enabled`, `priority`, `context_field`,
`context_pattern`, and `reason`.

Example:

```json
{
  "name": "Require approval for production writes",
  "enabled": true,
  "priority": 20,
  "effect": "require_approval",
  "match_field": "capability",
  "match_pattern": "prod:write",
  "reason": "A reviewer must authorize production changes."
}
```

Supported match fields are `agent_id`, `capability`, `resource`, `tool`,
`environment`, and `api_call`. `*` wildcards are supported. Rules are
evaluated in ascending priority, then creation time; the first matching rule
determines the result. Capability mappings for known calls are in
`backend/app/policy_engine.py`.

## Seed data

`python -m app.seed` initializes the schema and seeds tenant `acme` with:

- five demo agents for sales, support, operations, finance, and marketing;
- policies for bulk PII exports, destructive actions, production writes,
  operations scope, advertising exports, and finance reads;
- fourteen representative actions, including allowed, blocked, and
  approval-pending examples.

The exact resulting event and audit-record totals can be greater after repeat
runs or tests. Seed data is for demonstration and is not real customer data.

The sample users/tenant in the database do not create OIDC identities or
tokens. Configure the identity provider to issue the corresponding tenant
claim and scopes before using the authenticated dashboard or gateway.

## Tests

From the repository root:

```powershell
.\venv\Scripts\python.exe -m pytest backend\tests -q
node --check web\app.js
```

The backend suite uses a temporary SQLite database and covers policy
decisions, approval flows, tenant isolation, audit tamper detection, policy
simulation/versioning, JWT signature/issuer/audience/expiry and tenant claims,
scope restrictions, CORS behavior, and gateway fail-closed/authenticated
end-to-end behavior. The dashboard syntax check requires Node.js.

## Configuration reference

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUDITDEX_DB` | `backend/auditdex.sqlite3` | SQLite database path; set an absolute path for predictable deployments. |
| `OIDC_ISSUER` | `https://identity.example.com/` | Exact issuer URL expected in JWTs and OIDC discovery metadata. Set to `http://localhost:8080/realms/master` for the Docker Keycloak setup. |
| `OIDC_AUDIENCE` | `auditdex-api` | Required JWT access-token audience. |
| `OIDC_TENANT_CLAIM` | `tenant_id` | Signed claim containing an existing tenant ID. |
| `OIDC_CLIENT_ID` | `auditdex-spa` | Public SPA client ID used for browser sign-in. |
| `OIDC_REDIRECT_URI` | `http://127.0.0.1:8017/` | Exact browser callback registered on the OIDC client. |
| `OIDC_DISCOVERY_URL` | unset | Optional private discovery URL override for container networking; public issuer validation remains exact. |
| `OIDC_JWKS_URI` | unset | Optional private signing-key URL override for container networking. |
| `AUDITDEX_ALLOWED_ORIGINS` | empty | Comma-separated exact CORS origins; empty disables cross-origin API access. |
| `AUDITDEX_CONTROL_PLANE` | `http://127.0.0.1:8000` | API base URL used by the gateway. |
| `AUDITDEX_GATEWAY_TOKEN` | unset | Short-lived OIDC access token used by the gateway; unset means fail closed. |
| `OIDC_REALM` | `master` | Realm provisioned by `scripts/setup-keycloak.py`. |
| `KEYCLOAK_URL` | `http://localhost:8080` | Host URL for the local Keycloak admin API. |
| `KEYCLOAK_ADMIN_USERNAME` | `admin` | Local container bootstrap administrator. |
| `KEYCLOAK_ADMIN_PASSWORD` | `local-only-change-me` | Development container password; override before first startup. |
| `KEYCLOAK_DEMO_USERNAME` | `auditdex-demo` | Demo user provisioned for browser sign-in. |
| `KEYCLOAK_DEMO_PASSWORD` | `AuditDexLocal!2026` | Local demo user password; override if desired. |

## Security and prototype limitations

- **The OIDC provider is not configured by this repository.** Use a real HTTPS
  issuer in production, register the SPA and API audience, set tenant
  claims/scopes, and configure provider endpoint CORS. The included Keycloak
  container is for local development only.
- **Use HTTPS outside local development.** Bearer tokens must not cross
  untrusted networks in plaintext. Restrict ingress to the API and protect
  workload tokens.
- **The gateway adapter is a mock.** `execute_tool()` does not connect to an
  MCP server or SaaS API. A production integration needs an actual mediated
  adapter and must prevent agents from bypassing it with direct credentials.
- **Default policy posture is allow.** An action with no matching policy is
  allowed and tagged `default-allow`. Dashboard coverage metrics identify
  these gaps; they do not mean that unmatched actions are protected.
- **Log-only mode is not enforcement.** The mock adapter runs after an
  observation is recorded, irrespective of the policy result.
- **Approvals do not resume execution.** The API records an approval or
  rejection; the orchestrator must safely manage any later resumption.
- **SQLite hash chaining is not immutable evidence.** It detects changes
  relative to the stored chain but is not independent WORM storage. Production
  audit evidence needs external anchoring, key management, backups, and
  access controls.
- **The audit chain is global to the SQLite database.** API export filters
  records by tenant, while verification covers the database's complete chain.
- **OIDC token validation is intentionally generic.** Provider-specific
  workload identity, token refresh/rotation, principal lifecycle, rate
  limiting, monitoring, and deployment hardening remain deployment tasks.
- **No formal compliance claim is made.** Dashboard metrics and audit exports
  are prototype evidence, not a certification or independent assurance.

## Project layout

```text
backend/
  app/
    auth.py           OIDC token verification and tenant/scope authorization
    audit_log.py      append-only SHA-256 hash-chain operations
    db.py             SQLite schema, connection, and transaction helpers
    main.py           FastAPI endpoints, CORS, and static dashboard serving
    policy_engine.py  deterministic capability/policy evaluation
    seed.py           demo tenant, agents, policies, and actions
    services.py       tenant-scoped application operations
  tests/
    test_core.py      policy, API, auth, tenant, audit, and gateway tests
  requirements.txt    Python dependencies
gateway/
  gateway.py          authenticated policy-decision client and mock adapter
backend/Dockerfile    API/dashboard image
docker-compose.yml   API and local Keycloak services with persistent volumes
web/
  index.html          dashboard page structure
  app.js              OIDC SPA flow, API client, and dashboard rendering
  styles.css          responsive dashboard styling
```

## Troubleshooting

### Sign-in redirects but the dashboard shows an error

- Check that `OIDC_ISSUER` exactly matches the issuer value in the provider's
  discovery document and tokens, including trailing-slash conventions.
- Confirm the registered callback URL exactly matches the page origin and
  path.
- Ensure the provider issues an access-token JWT with the configured
  `OIDC_AUDIENCE`, a tenant claim naming a seeded/registered tenant, and
  supported signing algorithm RS256 or ES256.
- Allow the dashboard origin at the provider's token endpoint. Inspect browser
  developer tools for provider CORS or redirect errors.
- Check API logs for provider discovery/JWKS availability. Public provider
  endpoints must use HTTPS; Docker's configured private service URLs are
  available only on the Compose network.

### API returns `401 Unauthorized`

Provide `Authorization: Bearer <access-token>`. Check expiration, signature,
issuer, audience, and whether the value is an **access token** rather than an
ID token.

### API returns `403 Forbidden`

Check that the signed tenant claim maps to a row in the database and that the
token includes the required scope for the requested operation. Gateway calls
must send the same tenant in their body and token.

### Gateway fails closed

Set `AUDITDEX_GATEWAY_TOKEN` to a current access token containing
`auditdex:gateway`, make sure its tenant matches the call, and confirm
`AUDITDEX_CONTROL_PLANE` points to the running API. The gateway deliberately
does not proceed when authentication or control-plane evaluation fails.

### Dashboard starts without a data directory

The API creates its schema on startup. Run `python -m app.seed` from the
`backend` directory to populate a demo tenant before signing in.








