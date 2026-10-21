"""Deterministic policy evaluation.

Rules are pure functions of (agent, call, policy set): same inputs always
produce the same decision. No LLM is consulted on the enforcement path; an
optional analysis layer can annotate decisions afterwards, but it can never
change them. First-match-wins ordered by (priority asc, created_at asc).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field

# Capability model: every api_call maps to one or more capabilities.
# Patterns support '*' wildcards via fnmatch.
CAPABILITY_MAP: dict[str, list[str]] = {
    "crm.read_contacts": ["crm:read"],
    "crm.read_record": ["crm:read"],
    "crm.update_record": ["crm:write"],
    "crm.export_customers": ["crm:read", "data:export", "pii:export"],
    "crm.delete_records": ["crm:read", "crm:delete", "data:delete"],
    "internal_db.update_production_record": ["db:write", "prod:write"],
    "internal_db.read": ["db:read"],
    "internal_db.delete": ["db:write", "data:delete", "prod:write"],
    "erp.read_invoice": ["erp:read"],
    "erp.write_journal": ["erp:write"],
    "zendesk.get_ticket": ["support:read"],
    "zendesk.reply_ticket": ["support:write"],
    "ads.bulk_export": ["ads:read", "data:export"],
    "ads.read_report": ["ads:read"],
    "files.read": ["fs:read"],
    "files.delete": ["fs:write", "data:delete"],
}

# Fields a policy may match on, resolved from the evaluated call context.
RESOURCE_PREFIXES = ("pii", "prod", "sensitive", "internal", "public")


@dataclass
class CallContext:
    agent_id: str
    capabilities: list[str]
    api_call: str
    tool: str
    resource: str | None = None
    environment: str = "production"
    args: dict = field(default_factory=dict)

    def resolved_capabilities(self) -> list[str]:
        caps = set(self.capabilities)
        caps.update(CAPABILITY_MAP.get(self.api_call, []))
        return sorted(caps)

    def fields(self) -> dict[str, str]:
        f = {
            "agent_id": self.agent_id,
            "capability": "",  # handled specially: matches any resolved capability
            "resource": self.resource or infer_resource(self.api_call, self.args),
            "tool": self.tool,
            "environment": self.environment,
            "api_call": self.api_call,
        }
        return f


def infer_resource(api_call: str, args: dict) -> str:
    """Best-effort resource classification from call name and arguments."""
    text = api_call + " " + " ".join(str(v) for v in args.values())
    low = text.lower()
    if "customer" in low or "contact" in low or "pii" in low or "email" in low:
        return "pii/customers"
    if "production" in low or "prod" in low:
        return "prod/records"
    if "invoice" in low or "journal" in low or "finance" in low:
        return "sensitive/finance"
    if "ticket" in low:
        return "internal/support"
    return "general"


def pattern_match(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    return fnmatch.fnmatch(value, pattern)


def evaluate(ctx: CallContext, policies: list[dict]) -> dict:
    """Return {decision, policy_id, reason}.

    decision: allowed | blocked | pending_approval
    policy_id: '<id>#v<version>' of the deciding rule, or 'default-allow'
    """
    ordered = sorted(policies, key=lambda p: (p["priority"], p["created_at"]))
    caps = ctx.resolved_capabilities()

    for p in ordered:
        if not p["enabled"]:
            continue
        mf, mp = p["match_field"], p["match_pattern"]
        if mf == "capability":
            hit = any(pattern_match(mp, c) for c in caps)
        else:
            fields = ctx.fields()
            if mf not in fields:
                continue
            hit = pattern_match(mp, fields[mf])
        if not hit:
            continue
        # optional second condition
        if p.get("context_field"):
            cf, cp = p["context_field"], p["context_pattern"] or "*"
            fields = ctx.fields()
            if cf == "capability":
                if not any(pattern_match(cp, c) for c in caps):
                    continue
            elif cf not in fields or not pattern_match(cp, fields[cf]):
                continue
        effect = p["effect"]
        if effect == "deny":
            return {"decision": "blocked", "policy_id": policy_ref(p), "reason": p["reason"]}
        if effect == "require_approval":
            return {"decision": "pending_approval", "policy_id": policy_ref(p), "reason": p["reason"]}
        if effect == "allow":
            return {"decision": "allowed", "policy_id": policy_ref(p), "reason": p["reason"]}
    # No rule matched. Default posture: allow, but recorded as default-allow so
    # coverage gaps are visible in reports.
    return {"decision": "allowed", "policy_id": "default-allow", "reason": "No policy matched; default allow (coverage gap flagged in reports)"}


def policy_ref(p: dict) -> str:
    return f"{p['id']}#v{p['version']}"


def policy_hash(policies: list[dict]) -> str:
    """Stable fingerprint of the policy set used for a decision."""
    canonical = [{k: p.get(k) for k in (
        "id", "version", "enabled", "priority", "effect", "match_field",
        "match_pattern", "context_field", "context_pattern", "reason",
    )} for p in sorted(policies, key=lambda p: (p["priority"], p["created_at"]))]
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def alternatives(api_call: str) -> list[str]:
    """Suggest read-only calls when a write/export is denied."""
    if api_call.startswith("crm.") and ("export" in api_call or "delete" in api_call):
        return ["crm.read_contacts", "crm.read_record"]
    if api_call.startswith("ads.") and "export" in api_call:
        return ["ads.read_report"]
    if api_call.startswith("internal_db.") and ("update" in api_call or "delete" in api_call):
        return ["internal_db.read"]
    if api_call.startswith("erp.") and "write" in api_call:
        return ["erp.read_invoice"]
    return []


def validate_policy(p: dict) -> str | None:
    """Return an error message if the policy definition is invalid."""
    if p.get("effect") not in ("deny", "require_approval", "allow"):
        return "effect must be deny|require_approval|allow"
    if p.get("match_field") not in ("agent_id", "capability", "resource", "tool", "environment", "api_call"):
        return "match_field must be one of agent_id|capability|resource|tool|environment|api_call"
    if not p.get("match_pattern"):
        return "match_pattern is required"
    if p.get("context_field") and p["context_field"] not in ("agent_id", "capability", "resource", "tool", "environment", "api_call"):
        return "context_field invalid"
    if not re.search(r"[*]", p["match_pattern"]) and len(p["match_pattern"]) > 200:
        return "match_pattern too long"
    return None
