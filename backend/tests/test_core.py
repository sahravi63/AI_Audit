"""Tests tied to the initial evaluation criteria:

1. 100% of defined prohibited actions blocked in a controlled suite.
2. Every policy decision linked to an event record + applicable policy version.
3. Zero cross-tenant data access.
4. Integrity chain verifies; tampering is detected.
5. Policy simulation reports would-block / would-pass changes.
6. Gateway fails closed when the control plane is down.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import time
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

_tmp = tempfile.mkdtemp(prefix="auditdex_test_")
os.environ["AUDITDEX_DB"] = str(Path(_tmp) / "test.sqlite3")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app import audit_log, auth, db, services  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()
auth.signing_key_for_token = lambda _token: _public_key


def _token(tenant_id: str | None, scopes: str = "auditdex:write auditdex:gateway",
           audience: str | None = None, issuer: str | None = None,
           expires_in: int = 300, key=None) -> str:
    config = auth.settings()
    now = int(time.time())
    payload = {
        "iss": issuer or config.issuer,
        "aud": audience or config.audience,
        "exp": now + expires_in,
        "iat": now,
        "scope": scopes,
    }
    if tenant_id is not None:
        payload[config.tenant_claim] = tenant_id
    return jwt.encode(payload, key or _private_key, algorithm="RS256", headers={"kid": "test-key"})


H = {"Authorization": f"Bearer {_token('acme')}"}
HB = {"Authorization": f"Bearer {_token('globex')}"}


@pytest.fixture(scope="module", autouse=True)
def _seed():
    db.init_db()
    for tid, name in [("acme", "Acme Corp"), ("globex", "Globex Inc")]:
        conn = db.connect()
        conn.execute("INSERT OR REPLACE INTO tenants (id, name) VALUES (?,?)", (tid, name))
        conn.commit()
        conn.close()
    services.register_agent("acme", dict(id="agt_sales", name="Sales Agent", owner="j", environment="production",
                                         tools=["Salesforce"], capabilities=["crm:read"], risk_level="high"))
    services.register_agent("acme", dict(id="agt_ops", name="Ops Agent", owner=None, environment="production",
                                         tools=["Internal DB"], capabilities=["db:read"], risk_level="medium"))
    services.register_agent("acme", dict(id="agt_support", name="Support Agent", owner="m", environment="production",
                                         tools=["Zendesk"], capabilities=["support:read"], risk_level="low"))
    services.register_agent("acme", dict(id="agt_marketing", name="Marketing Agent", owner="s", environment="production",
                                         tools=["Google Ads"], capabilities=["ads:read"], risk_level="medium"))
    services.register_agent("globex", dict(id="g_sales", name="G Sales", owner="x", environment="production",
                                           tools=["Salesforce"], capabilities=["crm:read"], risk_level="low"))
    policies = [
        dict(id="pol_export", name="No PII export", priority=10, effect="deny",
             match_field="capability", match_pattern="pii:export", reason="PII export denied"),
        dict(id="pol_ads_bulk", name="Ads bulk export denied", priority=12, effect="deny",
             match_field="api_call", match_pattern="ads.bulk_export", reason="bulk ad export denied"),
        dict(id="pol_prod_write", name="Prod writes need approval", priority=30, effect="require_approval",
             match_field="capability", match_pattern="prod:write", reason="approval required"),
        dict(id="pol_delete", name="Deletes need approval", priority=20, effect="require_approval",
             match_field="capability", match_pattern="data:delete", reason="approval required"),
    ]
    for p in policies:
        p["enabled"] = True
        p.setdefault("reason", "")
        services.upsert_policy("acme", p)
        services.upsert_policy("globex", dict(p))


# ---- criterion 1: prohibited actions are deterministically blocked -----------

PROHIBITED = [
    ("agt_sales", "Salesforce", "crm.export_customers", {"scope": "all"}),
    ("agt_marketing", "Google Ads", "ads.bulk_export", {"scope": "all"}),
]

PROHIBITED_UNLESS_APPROVED = [
    ("agt_ops", "Internal DB", "internal_db.delete", {}),
    ("agt_ops", "Internal DB", "internal_db.update_production_record", {}),
]

ALLOWED_LEGIT = [
    ("agt_support", "Zendesk", "zendesk.get_ticket", {"id": "T-1"}),
    ("agt_sales", "Salesforce", "crm.read_contacts", {}),
]


def test_all_prohibited_actions_blocked():
    for agent, tool, call, args in PROHIBITED:
        r = services.record_action("acme", agent, tool, call, args=args)
        assert r["decision"] == "blocked", (agent, call, r)
        assert r["policy_id"].startswith("pol_")


def test_destructive_actions_require_approval_not_silent_allow():
    for agent, tool, call, args in PROHIBITED_UNLESS_APPROVED:
        r = services.record_action("acme", agent, tool, call, args=args)
        assert r["decision"] == "pending_approval", (agent, call, r)


def test_legitimate_actions_allowed():
    for agent, tool, call, args in ALLOWED_LEGIT:
        r = services.record_action("acme", agent, tool, call, args=args)
        assert r["decision"] == "allowed", (agent, call, r)


def test_approval_flow():
    r = services.record_action("acme", "agt_ops", "Internal DB", "internal_db.update_production_record", {})
    assert r["decision"] == "pending_approval"
    conn = db.connect()
    ap = conn.execute("SELECT * FROM approvals WHERE event_id=?", (r["event_id"],)).fetchone()
    conn.close()
    assert ap and ap["status"] == "pending"
    out = client.post(f"/api/approvals/{ap['id']}/decide", headers=H,
                      json={"decided_by": "ciso@acme", "approve": True, "note": "ok"})
    assert out.status_code == 200 and out.json()["status"] == "approved"
    # double-decide rejected
    out2 = client.post(f"/api/approvals/{ap['id']}/decide", headers=H, json={"approve": False})
    assert out2.status_code == 409


def test_unknown_agent_fail_closed():
    resp = client.post("/internal/evaluate", json={
        "tenant_id": "acme", "agent_id": "ghost", "tool": "X", "api_call": "internal_db.read", "args": {}},
        headers=H)
    assert resp.status_code == 403


# ---- criterion 2: every decision linked to event + policy version ------------

def test_every_decision_has_event_and_policy_version():
    events = client.get("/api/actions", headers=H).json()
    assert len(events) >= 5
    for e in events:
        assert e["policy_id"], e
        assert e["decision"] in ("allowed", "blocked", "pending_approval", "approved", "rejected")
        if e["policy_id"] != "default-allow":
            pid, ver = e["policy_id"].split("#v")
            pol = client.get("/api/policies", headers=H).json()
            assert any(p["id"] == pid and p["version"] == int(ver) for p in pol), e["policy_id"]


# ---- criterion 3: tenant isolation --------------------------------------------

def test_cross_tenant_reads_empty():
    # globex cannot see acme agents/events/approvals
    ids = [a["id"] for a in client.get("/api/agents", headers=HB).json()]
    assert "agt_sales" not in ids
    assert all(e["tenant_id"] == "globex" for e in client.get("/api/actions", headers=HB).json())
    assert client.get("/api/approvals", headers=HB).json() == []


def test_untrusted_tenant_header_cannot_change_token_scope():
    headers = {**H, "X-Tenant-Id": "globex"}
    ids = [a["id"] for a in client.get("/api/agents", headers=headers).json()]
    assert "agt_sales" in ids
    assert "g_sales" not in ids


def test_api_requires_valid_bearer_token():
    assert client.get("/api/agents").status_code == 401
    assert client.get("/api/agents", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_current_identity_returns_claimed_tenant():
    identity = client.get("/auth/me", headers=H)
    assert identity.status_code == 200
    assert identity.json() == {"tenant_id": "acme", "tenant_name": "Acme Corp"}


def test_token_signature_issuer_audience_and_tenant_are_verified():
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {_token('acme', key=other_key)}"}).status_code == 401
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {_token('acme', issuer='https://attacker.example/')}"}).status_code == 401
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {_token('acme', audience='other-api')}"}).status_code == 401
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {_token(None)}"}).status_code == 403
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {_token('acme', expires_in=-1)}"}).status_code == 401


def test_oidc_config_is_public_but_cors_is_not_wildcard():
    config = client.get("/auth/config")
    assert config.status_code == 200
    assert config.json()["audience"] == auth.settings().audience
    preflight = client.options("/api/agents", headers={
        "Origin": "https://untrusted.example",
        "Access-Control-Request-Method": "GET",
    })
    assert "access-control-allow-origin" not in preflight.headers


def test_mutations_require_write_scope():
    headers = {"Authorization": f"Bearer {_token('acme', 'auditdex:read')}"}
    resp = client.post("/api/agents", headers=headers, json={"name": "Read only"})
    assert resp.status_code == 403


def test_gateway_requires_scope_and_matching_tenant():
    read_only = {"Authorization": f"Bearer {_token('acme', 'auditdex:read')}"}
    body = {"tenant_id": "acme", "agent_id": "agt_sales", "tool": "Salesforce",
            "api_call": "crm.read_contacts", "args": {}}
    assert client.post("/internal/evaluate", headers=read_only, json=body).status_code == 403
    assert client.post("/internal/evaluate", headers=HB, json=body).status_code == 403


def test_cross_tenant_decide_rejected():
    r = services.record_action("acme", "agt_ops", "Internal DB", "internal_db.delete", {})
    conn = db.connect()
    ap = conn.execute("SELECT id FROM approvals WHERE event_id=?", (r["event_id"],)).fetchone()["id"]
    conn.close()
    out = client.post(f"/api/approvals/{ap}/decide", headers=HB, json={"approve": True})
    assert out.status_code == 404


def test_missing_authentication_rejected():
    assert client.get("/api/agents").status_code == 401


# ---- criterion 4: integrity chain ----------------------------------------------

def test_chain_valid_and_tamper_detected():
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["valid"] and v["checked"] > 0
    conn = db.connect()
    conn.execute("UPDATE audit_log SET payload='{\"tampered\":true}' WHERE seq=3")
    conn.commit()
    v2 = audit_log.verify_chain(conn)
    assert v2["valid"] is False and v2["broken_at_seq"] == 3
    # restore so later tests pass
    conn.execute("DELETE FROM audit_log WHERE seq>=3")
    conn.commit()
    conn.close()


# ---- criterion 5: policy simulation ---------------------------------------------

def test_simulate_reports_changes_without_persisting():
    spec = dict(id="sim_pol", name="Block support reads", enabled=True, priority=5, effect="deny",
                match_field="agent_id", match_pattern="agt_support", reason="test sim")
    r = client.post("/api/policies/simulate", headers=H, json={"policy": spec}).json()
    assert r["sampled_actions"] > 0
    assert any(c["old_decision"] == "allowed" and c["new_decision"] == "blocked" for c in r["changes"])
    # candidate was NOT persisted
    assert all(p["id"] != "sim_pol" for p in client.get("/api/policies", headers=H).json())


def test_policy_update_bumps_version():
    p1 = client.post("/api/policies", headers=H, json=dict(
        id="pol_ver", name="V", enabled=True, priority=50, effect="deny",
        match_field="resource", match_pattern="nothing", reason="")).json()
    p2 = client.post("/api/policies", headers=H, json=dict(
        id="pol_ver", name="V", enabled=True, priority=50, effect="deny",
        match_field="resource", match_pattern="nothing", reason="")).json()
    assert p1["version"] == 1 and p2["version"] == 2


# ---- criterion 6: gateway fail-closed ----------------------------------------------

def test_gateway_fails_closed_when_control_plane_down(monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "gateway"))
    import gateway as gw

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setenv("AUDITDEX_GATEWAY_TOKEN", H["Authorization"].removeprefix("Bearer "))
    monkeypatch.setattr(gw.urllib.request, "urlopen", boom)
    with pytest.raises(gw.GatewayError) as exc:
        gw.handle_tool_call("acme", "agt_sales", "Salesforce", "crm.export_customers", {})
    assert "fail-closed" in str(exc.value)


def test_gateway_sends_configured_oidc_bearer_token(monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "gateway"))
    import gateway as gw

    token = H["Authorization"].removeprefix("Bearer ")
    monkeypatch.setenv("AUDITDEX_GATEWAY_TOKEN", token)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'{"decision":"allowed"}'

    def capture(req, timeout):
        assert req.get_header("Authorization") == f"Bearer {token}"
        assert timeout == 5.0
        return Response()

    monkeypatch.setattr(gw.urllib.request, "urlopen", capture)
    assert gw._post("/internal/evaluate", {}) == {"decision": "allowed"}


def test_gateway_e2e_uses_oidc_scope_and_policy_decision(monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "gateway"))
    import gateway as gw

    monkeypatch.setenv("AUDITDEX_GATEWAY_TOKEN", H["Authorization"].removeprefix("Bearer "))

    class Response:
        def __init__(self, response):
            self.response = response

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return self.response.content

    def call_control_plane(req, timeout):
        response = client.post(
            urlsplit(req.full_url).path,
            content=req.data,
            headers={
                "Authorization": req.get_header("Authorization"),
                "Content-Type": "application/json",
            },
        )
        if response.status_code >= 400:
            raise urllib.error.HTTPError(
                req.full_url, response.status_code, "control plane error", None, io.BytesIO(response.content),
            )
        return Response(response)

    monkeypatch.setattr(gw.urllib.request, "urlopen", call_control_plane)
    allowed = gw.handle_tool_call("acme", "agt_support", "Zendesk", "zendesk.get_ticket", {})
    blocked = gw.handle_tool_call("acme", "agt_sales", "Salesforce", "crm.export_customers", {})
    observed = gw.handle_tool_call("acme", "agt_support", "Zendesk", "zendesk.reply_ticket", {}, mode="log_only")
    assert allowed["decision"] == "allowed" and allowed["result"] is not None
    assert blocked["decision"] == "blocked" and blocked["result"] is None
    assert observed["decision"] == "observed" and observed["result"] is not None


def test_overview_endpoints_ok():
    ov = client.get("/api/overview", headers=H).json()
    assert ov["registered_agents"] >= 3
    assert 0 <= ov["policy_coverage_pct"] <= 100
    inc = client.get("/api/incidents", headers=H).json()
    assert all(i["timeline"][0]["trace_id"] if "trace_id" in i["timeline"][0] else True for i in inc)
    exp = client.get("/api/audit/export", headers=H).json()
    assert exp["verification"]["valid"] is True
