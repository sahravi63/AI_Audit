"""Service layer: tenant-scoped operations shared by the API and the gateway."""

from __future__ import annotations

import time

from . import audit_log, db, policy_engine
from .policy_engine import CallContext, evaluate


def record_action(tenant_id: str, agent_id: str, tool: str, api_call: str,
                  args: dict | None = None, resource: str | None = None,
                  user_request: str | None = None, trace_id: str | None = None,
                  mode: str = "enforce", source: str = "gateway") -> dict:
    """Evaluate policies for one agent action and persist the decision.

    Returns the event dict including decision, policy reference and evidence.
    Event insert + approval row + audit append commit atomically via db.tx().
    """
    t0 = time.perf_counter()
    conn = db.connect()
    try:
        agent = conn.execute("SELECT * FROM agents WHERE id=? AND tenant_id=?", (agent_id, tenant_id)).fetchone()
        if not agent:
            raise LookupError(f"unknown agent {agent_id} for tenant {tenant_id}")
        agent_d = db.rows_to_dicts([agent])[0]
        env = "sandbox" if agent_d["environment"] == "sandbox" else "production"
        ctx = CallContext(
            agent_id=agent_id,
            capabilities=agent_d["capabilities"],
            api_call=api_call,
            tool=tool,
            resource=resource,
            environment=env,
            args=args or {},
        )
        policies = db.rows_to_dicts(
            conn.execute("SELECT * FROM policies WHERE tenant_id=? ORDER BY priority, created_at", (tenant_id,)).fetchall()
        )
        result = evaluate(ctx, policies)
        policy_fingerprint = policy_engine.policy_hash(policies)
        if mode == "log_only":
            result = {"decision": "observed", "policy_id": "log-only", "reason": "Observed in discovery mode; no policy was enforced"}
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        event_id = db.new_id("evt")
        trace_id = trace_id or db.new_id("trc")
        decision = result["decision"]

        with db.tx(conn):
            conn.execute(
                "INSERT INTO action_events (id, tenant_id, trace_id, agent_id, user_request, tool, api_call,"
                " resource, args, decision, policy_id, evidence, latency_ms, created_at, policy_hash, mode, source)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event_id, tenant_id, trace_id, agent_id, user_request, tool, api_call,
                 ctx.fields()["resource"], audit_log.canonical_json(args or {}), decision,
                 result["policy_id"], result["reason"], latency_ms, audit_log.now_iso(),
                 policy_fingerprint, mode, source),
            )
            if decision == "pending_approval":
                conn.execute(
                    "INSERT INTO approvals (id, tenant_id, event_id, status, requested_at) VALUES (?,?,?,?,?)",
                    (db.new_id("apr"), tenant_id, event_id, "pending", audit_log.now_iso()),
                )
            audit_log.append(conn, "action", {
                "event_id": event_id, "trace_id": trace_id, "tenant_id": tenant_id,
                "agent_id": agent_id, "api_call": api_call, "tool": tool,
                "decision": decision, "policy_id": result["policy_id"], "evidence": result["reason"],
                "policy_hash": policy_fingerprint, "mode": mode, "args": args or {},
            })
        return {
            "event_id": event_id, "trace_id": trace_id, "decision": decision,
            "policy_id": result["policy_id"], "evidence": result["reason"],
            "latency_ms": latency_ms, "resource": ctx.fields()["resource"],
            "policy_hash": policy_fingerprint, "mode": mode,
            "allowed_alternatives": policy_engine.alternatives(api_call) if decision == "blocked" else [],
        }
    finally:
        conn.close()


def execute_approval(approval_id: str, tenant_id: str, decided_by: str, approve: bool, note: str = "") -> dict:
    conn = db.connect()
    try:
        with db.tx(conn):
            row = conn.execute("SELECT * FROM approvals WHERE id=? AND tenant_id=?", (approval_id, tenant_id)).fetchone()
            if not row:
                raise LookupError("approval not found")
            if row["status"] != "pending":
                raise ValueError("approval already decided")
            status = "approved" if approve else "rejected"
            conn.execute(
                "UPDATE approvals SET status=?, decided_by=?, decided_at=?, note=? WHERE id=?",
                (status, decided_by, audit_log.now_iso(), note, approval_id),
            )
            conn.execute("UPDATE action_events SET decision=? WHERE id=?", (status, row["event_id"]))
            audit_log.append(conn, "approval", {
                "approval_id": approval_id, "event_id": row["event_id"], "tenant_id": tenant_id,
                "decision": status, "decided_by": decided_by, "note": note,
            })
        return {"approval_id": approval_id, "status": status}
    finally:
        conn.close()


def upsert_policy(tenant_id: str, spec: dict, created_by: str = "system") -> dict:
    err = policy_engine.validate_policy(spec)
    if err:
        raise ValueError(err)
    conn = db.connect()
    try:
        existing = None
        if spec.get("id"):
            existing = conn.execute(
                "SELECT * FROM policies WHERE id=? AND tenant_id=?", (spec["id"], tenant_id)).fetchone()
        with db.tx(conn):
            if existing:
                new_version = existing["version"] + 1
                pid = spec["id"]
                conn.execute(
                    "UPDATE policies SET name=?, version=?, enabled=?, priority=?, effect=?, match_field=?,"
                    " match_pattern=?, context_field=?, context_pattern=?, reason=? WHERE id=?",
                    (spec["name"], new_version, int(bool(spec.get("enabled", True))), spec.get("priority", 100),
                     spec["effect"], spec["match_field"], spec["match_pattern"],
                     spec.get("context_field"), spec.get("context_pattern"), spec.get("reason", ""), pid),
                )
            else:
                pid = spec.get("id") or db.new_id("pol")
                conn.execute(
                    "INSERT INTO policies (id, tenant_id, name, version, enabled, priority, effect, match_field,"
                    " match_pattern, context_field, context_pattern, reason, created_by, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, tenant_id, spec["name"], 1, int(bool(spec.get("enabled", True))), spec.get("priority", 100),
                     spec["effect"], spec["match_field"], spec["match_pattern"],
                     spec.get("context_field"), spec.get("context_pattern"), spec.get("reason", ""),
                     created_by, audit_log.now_iso()),
                )
            audit_log.append(conn, "policy", {"policy_id": pid, "tenant_id": tenant_id, "action": "upsert",
                                              "effect": spec["effect"],
                                              "match": f"{spec['match_field']}={spec['match_pattern']}"})
        row = conn.execute("SELECT * FROM policies WHERE id=? AND tenant_id=?", (pid, tenant_id)).fetchone()
        return db.rows_to_dicts([row])[0]
    finally:
        conn.close()


def register_agent(tenant_id: str, spec: dict) -> dict:
    conn = db.connect()
    try:
        aid = spec.get("id") or db.new_id("agt")
        with db.tx(conn):
            conn.execute(
                "INSERT INTO agents (id, tenant_id, name, owner, purpose, environment, tools, capabilities,"
                " risk_level, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (aid, tenant_id, spec["name"], spec.get("owner"), spec.get("purpose", ""),
                 spec.get("environment", "production"), audit_log.canonical_json(spec.get("tools", [])),
                 audit_log.canonical_json(spec.get("capabilities", [])), spec.get("risk_level", "low"),
                 audit_log.now_iso()),
            )
            audit_log.append(conn, "agent", {"agent_id": aid, "tenant_id": tenant_id, "action": "register",
                                             "name": spec["name"], "capabilities": spec.get("capabilities", [])})
        row = conn.execute("SELECT * FROM agents WHERE id=?", (aid,)).fetchone()
        return db.rows_to_dicts([row])[0]
    finally:
        conn.close()


def simulate_policy(tenant_id: str, spec: dict, sample_limit: int = 5000) -> dict:
    """Replay recorded actions against a candidate policy set (shadow mode).

    The candidate replaces/inserts into the current enabled rules without
    touching persisted state; every historical action is re-evaluated and we
    report which legitimate workflows would break and which unsafe actions
    would newly pass.
    """
    err = policy_engine.validate_policy(spec)
    if err:
        raise ValueError(err)
    conn = db.connect()
    try:
        policies = db.rows_to_dicts(
            conn.execute("SELECT * FROM policies WHERE tenant_id=? AND enabled=1", (tenant_id,)).fetchall()
        )
        candidate = dict(spec)
        candidate.setdefault("id", "simulated")
        candidate.setdefault("version", 1)
        candidate.setdefault("created_at", "0000")
        candidate.setdefault("priority", 100)
        candidate.setdefault("enabled", 1)
        candidate.setdefault("context_field", None)
        candidate.setdefault("context_pattern", None)
        base = [p for p in policies if p["id"] != candidate["id"]]
        with_candidate = sorted(base + [candidate], key=lambda p: (p["priority"], p["created_at"]))

        events = db.rows_to_dicts(
            conn.execute(
                "SELECT e.*, a.capabilities, a.environment FROM action_events e JOIN agents a ON a.id=e.agent_id"
                " WHERE e.tenant_id=? ORDER BY e.created_at LIMIT ?", (tenant_id, sample_limit)).fetchall()
        )
        changed, newly_blocked, still_passing = [], [], []
        for ev in events:
            ctx = CallContext(
                agent_id=ev["agent_id"], capabilities=ev["capabilities"], api_call=ev["api_call"],
                tool=ev["tool"], resource=ev["resource"],
                environment="sandbox" if ev["environment"] == "sandbox" else "production",
                args=ev["args"],
            )
            old = evaluate(ctx, policies)["decision"]
            new = evaluate(ctx, with_candidate)["decision"]
            if old != new:
                entry = {"event_id": ev["id"], "agent_id": ev["agent_id"], "api_call": ev["api_call"],
                         "old_decision": old, "new_decision": new}
                changed.append(entry)
                if new == "blocked" and old == "allowed":
                    newly_blocked.append(entry)
                if new == "allowed" and old in ("blocked", "pending_approval"):
                    still_passing.append(entry)
        return {
            "sampled_actions": len(events),
            "decisions_changed": len(changed),
            "would_block_legitimate": newly_blocked,           # false-positive candidates
            "would_allow_previously_denied": still_passing,    # coverage regressions
            "changes": changed,
        }
    finally:
        conn.close()
