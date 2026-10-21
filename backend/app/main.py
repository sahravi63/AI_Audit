"""AuditDex AI control-plane API.

Endpoints are tenant-scoped using verified OIDC tenant claims. The gateway uses
/internal/evaluate and must present a token with the gateway scope.
"""

from __future__ import annotations

import os

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
from fastapi.staticfiles import StaticFiles

from . import audit_log, auth, db, services

app = FastAPI(title="AuditDex AI", version="0.1.0")
allowed_origins = [
    origin.strip()
    for origin in os.getenv("AUDITDEX_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
WEB_DIR = Path(__file__).resolve().parents[2] / "web"
app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.get("/auth/config")
def oidc_config():
    return auth.public_config()


@app.get("/auth/me")
def current_identity(principal: auth.Principal = Depends(auth.authenticated_principal)):
    return {"tenant_id": principal.tenant_id, "tenant_name": principal.tenant_name}


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


# ---- health / overview -----------------------------------------------------

@app.get("/api/overview")
def overview(tid: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        agents = conn.execute("SELECT COUNT(*) c FROM agents WHERE tenant_id=?", (tid,)).fetchone()["c"]
        total24 = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=? AND created_at >= datetime('now','-1 day')", (tid,)).fetchone()["c"]
        violations = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=? AND decision IN ('blocked','rejected')"
            " AND created_at >= datetime('now','-1 day')", (tid,)).fetchone()["c"]
        awaiting = conn.execute(
            "SELECT COUNT(*) c FROM approvals WHERE tenant_id=? AND status='pending'", (tid,)).fetchone()["c"]
        default_allow = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=? AND policy_id='default-allow'", (tid,)).fetchone()["c"]
        events = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=?", (tid,)).fetchone()["c"]
        covered24 = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=? AND policy_id!='default-allow'"
            " AND created_at >= datetime('now','-1 day')", (tid,)).fetchone()["c"]
        uncovered24 = conn.execute(
            "SELECT COUNT(*) c FROM action_events WHERE tenant_id=? AND policy_id='default-allow'"
            " AND created_at >= datetime('now','-1 day')", (tid,)).fetchone()["c"]
        coverage = round(100.0 * covered24 / total24, 1) if total24 else 0.0
        recent = db.rows_to_dicts(conn.execute(
            "SELECT e.*, a.name agent_name FROM action_events e JOIN agents a ON a.id=e.agent_id"
            " WHERE e.tenant_id=? ORDER BY e.created_at DESC LIMIT 8", (tid,)).fetchall())
        risky = db.rows_to_dicts(conn.execute(
            "SELECT a.id, a.name, a.risk_level, COUNT(e.id) issues FROM agents a"
            " LEFT JOIN action_events e ON e.agent_id=a.id AND e.tenant_id=a.tenant_id"
            " AND e.decision IN ('blocked','rejected') AND e.created_at >= datetime('now','-1 day')"
            " WHERE a.tenant_id=? GROUP BY a.id ORDER BY issues DESC LIMIT 6", (tid,)).fetchall())
        chain = audit_log.verify_chain(conn)
        return {
            "registered_agents": agents, "actions_24h": total24, "policy_violations": violations,
            "awaiting_approval": awaiting, "unverified_actions": uncovered24,
            "policy_coverage_pct": coverage,
            "policy_coverage": {"evaluated_actions_24h": covered24, "total_actions_24h": total24,
                                "unmatched_actions_24h": uncovered24},
            "chain_valid": chain["valid"], "log_records": chain["checked"],
            "recent_events": recent, "risky_agents": risky,
        }
    finally:
        conn.close()


# ---- agents ----------------------------------------------------------------

@app.get("/api/agents")
def list_agents(t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        return db.rows_to_dicts(conn.execute("SELECT * FROM agents WHERE tenant_id=? ORDER BY name", (t,)).fetchall())
    finally:
        conn.close()


@app.post("/api/agents")
def create_agent(spec: dict = Body(...), t: str = Depends(auth.require_scope("auditdex:write"))):
    try:
        return services.register_agent(t, spec)
    except Exception as e:
        raise HTTPException(400, str(e))


# ---- policies ---------------------------------------------------------------

@app.get("/api/policies")
def list_policies(t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        return db.rows_to_dicts(conn.execute(
            "SELECT * FROM policies WHERE tenant_id=? ORDER BY priority, created_at", (t,)).fetchall())
    finally:
        conn.close()


@app.post("/api/policies")
def put_policy(spec: dict = Body(...), t: str = Depends(auth.require_scope("auditdex:write"))):
    try:
        return services.upsert_policy(t, spec)
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.post("/api/policies/simulate")
def simulate(spec: dict = Body(...), t: str = Depends(auth.require_scope("auditdex:write"))):
    try:
        return services.simulate_policy(t, spec["policy"])
    except ValueError as e:
        raise HTTPException(422, str(e))


# ---- actions / events --------------------------------------------------------

@app.get("/api/actions")
def list_actions(limit: int = 100, agent_id: str | None = None, decision: str | None = None,
                 trace_id: str | None = None, q: str | None = None,
                 t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        sql = ("SELECT e.*, a.name agent_name FROM action_events e JOIN agents a ON a.id=e.agent_id"
               " WHERE e.tenant_id=?")
        args: list = [t]
        if agent_id:
            sql += " AND e.agent_id=?"; args.append(agent_id)
        if decision:
            sql += " AND e.decision=?"; args.append(decision)
        if trace_id:
            sql += " AND e.trace_id=?"; args.append(trace_id)
        if q:
            sql += " AND (e.api_call LIKE ? OR e.tool LIKE ? OR e.user_request LIKE ?)"
            args += [f"%{q}%"] * 3
        sql += " ORDER BY e.created_at DESC LIMIT ?"; args.append(min(limit, 1000))
        return db.rows_to_dicts(conn.execute(sql, args).fetchall())
    finally:
        conn.close()


@app.get("/api/traces/{trace_id}")
def get_trace(trace_id: str, t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        return db.rows_to_dicts(conn.execute(
            "SELECT e.*, a.name agent_name FROM action_events e JOIN agents a ON a.id=e.agent_id"
            " WHERE e.tenant_id=? AND e.trace_id=? ORDER BY e.created_at", (t, trace_id)).fetchall())
    finally:
        conn.close()


# ---- approvals ---------------------------------------------------------------

@app.get("/api/approvals")
def list_approvals(t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        rows = db.rows_to_dicts(conn.execute(
            "SELECT ap.*, e.api_call, e.tool, e.agent_id, e.args, a.name agent_name FROM approvals ap"
            " JOIN action_events e ON e.id=ap.event_id JOIN agents a ON a.id=e.agent_id"
            " WHERE ap.tenant_id=? ORDER BY ap.requested_at DESC", (t,)).fetchall())
        for row in rows:
            args = row.get("args") or {}
            row["impact"] = {"target": row["tool"], "records_affected": args.get("limit") or args.get("count") or args.get("scope") or "unknown"}
        return rows
    finally:
        conn.close()


@app.post("/api/approvals/{approval_id}/decide")
def decide(approval_id: str, body: dict = Body(...),
           t: str = Depends(auth.require_scope("auditdex:write"))):
    try:
        return services.execute_approval(approval_id, t, body.get("decided_by", "unknown"),
                                         bool(body.get("approve")), body.get("note", ""))
    except LookupError:
        raise HTTPException(404, "approval not found")
    except ValueError as e:
        raise HTTPException(409, str(e))


# ---- incidents (investigation timelines from evidence) -----------------------

@app.get("/api/incidents")
def list_incidents(tid: str = Depends(auth.authenticated_tenant)):
    """An incident = one blocked/rejected event plus its full trace context."""
    conn = db.connect()
    try:
        bad = db.rows_to_dicts(conn.execute(
            "SELECT * FROM action_events WHERE tenant_id=? AND decision IN ('blocked','rejected')"
            " ORDER BY created_at DESC", (tid,)).fetchall())
        out = []
        for ev in bad:
            trace = db.rows_to_dicts(conn.execute(
                "SELECT id, api_call, tool, decision, policy_id, evidence, created_at FROM action_events"
                " WHERE tenant_id=? AND trace_id=? ORDER BY created_at", (tid, ev["trace_id"])).fetchall())
            out.append({"event": ev, "timeline": trace})
        return out
    finally:
        conn.close()


# ---- integrity + exports ------------------------------------------------------

@app.get("/api/audit/verify")
def verify(t: str = Depends(auth.authenticated_tenant)):
    conn = db.connect()
    try:
        return audit_log.verify_chain(conn)
    finally:
        conn.close()


@app.get("/api/audit/export")
def export(tid: str = Depends(auth.authenticated_tenant)):
    """Downloadable JSON bundle with the full hash chain for offline verification."""
    conn = db.connect()
    try:
        records = audit_log.all_records(conn)
        # scope to tenant by payload tenant_id
        scoped = [r for r in records if r["payload"].get("tenant_id") == tid]
        events = db.rows_to_dicts(conn.execute(
            "SELECT * FROM action_events WHERE tenant_id=? ORDER BY created_at", (tid,)).fetchall())
        return {"tenant_id": tid, "exported_at": audit_log.now_iso(),
                "chain": {"total_records": len(records), "scoped_records": len(scoped)},
                "verification": audit_log.verify_chain(conn),
                "records": scoped, "action_events": events}
    finally:
        conn.close()


# ---- internal gateway endpoint --------------------------------------------------

@app.post("/internal/evaluate")
def evaluate_action(body: dict = Body(...), t: str = Depends(auth.require_scope("auditdex:gateway"))):
    """Called by the MCP gateway before executing a tool. Fail-closed on errors."""
    if body.get("tenant_id") != t:
        raise HTTPException(403, "Gateway token is not authorized for this tenant")
    try:
        return services.record_action(
            tenant_id=body["tenant_id"], agent_id=body["agent_id"], tool=body["tool"],
            api_call=body["api_call"], args=body.get("args", {}), resource=body.get("resource"),
            user_request=body.get("user_request"), trace_id=body.get("trace_id"),
        )
    except LookupError as e:
        raise HTTPException(403, f"fail-closed: {e}")
    except KeyError as e:
        raise HTTPException(422, f"missing field {e}")


@app.post("/internal/observe")
def observe_action(body: dict = Body(...), t: str = Depends(auth.require_scope("auditdex:gateway"))):
    """Record discovery telemetry without enforcing the policy result."""
    if body.get("tenant_id") != t:
        raise HTTPException(403, "Gateway token is not authorized for this tenant")
    try:
        return services.record_action(
            tenant_id=body["tenant_id"], agent_id=body["agent_id"], tool=body["tool"],
            api_call=body["api_call"], args=body.get("args", {}), resource=body.get("resource"),
            user_request=body.get("user_request"), trace_id=body.get("trace_id"),
            mode="log_only", source=body.get("source", "network_discovery"),
        )
    except LookupError as e:
        raise HTTPException(403, f"unknown identity: {e}")
    except KeyError as e:
        raise HTTPException(422, f"missing field {e}")
