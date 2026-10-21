"""AuditDex AI — instrumented MCP gateway.

Sits between AI agents and their tools (MCP servers / internal APIs). Every
tool call is identified, policy-checked at the control plane, executed only if
allowed, and recorded with full context. Fail-closed: if the control plane is
unreachable, the call is denied and logged locally as a fail-closed event.

Run standalone for demo:  python gateway.py  (proxies to the mock tool backend)
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

CONTROL_PLANE = os.getenv("AUDITDEX_CONTROL_PLANE", "http://127.0.0.1:8000")


class GatewayError(Exception):
    pass


def _post(path: str, body: dict, timeout: float = 5.0) -> dict:
    token = os.getenv("AUDITDEX_GATEWAY_TOKEN")
    if not token:
        raise GatewayError("fail-closed: AUDITDEX_GATEWAY_TOKEN is not configured")
    req = urllib.request.Request(
        CONTROL_PLANE + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def evaluate(tenant_id: str, agent_id: str, tool: str, api_call: str, args: dict,
             user_request: str | None = None, trace_id: str | None = None,
             mode: str = "enforce") -> dict:
    """Ask the control plane for a decision or a log-only observation."""
    try:
        path = "/internal/observe" if mode == "log_only" else "/internal/evaluate"
        return _post(path, {
            "tenant_id": tenant_id, "agent_id": agent_id, "tool": tool,
            "api_call": api_call, "args": args, "user_request": user_request,
            "trace_id": trace_id, "source": "gateway",
        })
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as e:
        code = getattr(e, "code", None)
        # 403 from control plane = unknown agent => deny, but it was still recorded
        if isinstance(e, urllib.error.HTTPError) and code == 403:
            raise GatewayError(f"fail-closed: control plane rejected identity ({e.read().decode()[:200]})")
        raise GatewayError(f"fail-closed: control plane unreachable ({e})")


def execute_tool(tool: str, api_call: str, args: dict) -> dict:
    """Forward the call to the actual tool backend (mock here; swap per integration)."""
    # In production this dispatches to the real MCP server / REST API connector.
    return {"ok": True, "tool": tool, "api_call": api_call, "result": f"executed {api_call} with {json.dumps(args)}"}


def handle_tool_call(tenant_id: str, agent_id: str, tool: str, api_call: str, args: dict | None = None,
                     user_request: str | None = None, trace_id: str | None = None,
                     mode: str = "enforce") -> dict:
    """The single enforcement point: identify -> check -> execute/deny -> record."""
    t0 = time.perf_counter()
    if mode not in ("enforce", "log_only"):
        raise ValueError("mode must be enforce or log_only")
    verdict = evaluate(tenant_id, agent_id, tool, api_call, args or {}, user_request, trace_id, mode)
    decision = verdict["decision"]
    envelope = {
        "decision": decision,
        "event_id": verdict["event_id"],
        "trace_id": verdict["trace_id"],
        "policy_id": verdict["policy_id"],
        "evidence": verdict["evidence"],
        "gateway_latency_ms": round((time.perf_counter() - t0) * 1000, 3),
    }
    if decision == "allowed" or mode == "log_only":
        envelope["result"] = execute_tool(tool, api_call, args or {})
        if mode == "log_only":
            envelope["message"] = "Discovery mode: action observed but policy was not enforced."
    elif decision == "pending_approval":
        envelope["result"] = None
        envelope["message"] = "Action queued for human approval; not executed."
    else:  # blocked
        envelope["result"] = None
        envelope["message"] = "Action blocked by policy. Attempt recorded in audit trail."
        envelope["error"] = {
            "code": "POLICY_VIOLATION", "reason": verdict["evidence"],
            "allowed_alternatives": verdict.get("allowed_alternatives", []),
            "event_id": verdict["event_id"], "trace_id": verdict["trace_id"],
        }
    return envelope


# ---- CLI demo ------------------------------------------------------------------

if __name__ == "__main__":
    scenarios = [
        ("agt_support", "Zendesk", "zendesk.get_ticket", {"id": "T-1"}, "Read ticket T-1"),
        ("agt_sales", "Salesforce", "crm.export_customers", {"scope": "all"}, "Export all customers"),
        ("agt_ops", "Internal DB", "internal_db.update_production_record", {"id": "o-1"}, "Update prod record"),
        ("ghost_agent", "Internal DB", "internal_db.read", {}, "Unknown agent attempts read"),
    ]
    for agent, tool, call, args, req in scenarios:
        print("\n===", agent, call, "| request:", req)
        try:
            out = handle_tool_call("acme", agent, tool, call, args, user_request=req)
            print(json.dumps(out, indent=2))
        except GatewayError as e:
            print("DENIED AT GATEWAY:", e)
