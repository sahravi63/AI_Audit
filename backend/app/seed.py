"""Seed demo data matching the AuditDex AI concept: agents, policies, and a
realistic day of agent actions including violations and approvals.

Run:  python -m app.seed   (from backend/)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, services  # noqa: E402

TENANT = "acme"


def seed() -> None:
    db.init_db()
    conn = db.connect()
    already_seeded = conn.execute(
        "SELECT 1 FROM agents WHERE id='agt_sales' AND tenant_id=?", (TENANT,)
    ).fetchone()
    if already_seeded:
        conn.close()
        print("demo workspace already seeded:", TENANT)
        return
    conn.execute("INSERT OR REPLACE INTO tenants (id, name) VALUES (?,?)", (TENANT, "Acme Corp"))
    conn.commit()
    conn.close()

    agents = [
        dict(id="agt_sales", name="Sales Agent", owner="j.rivera", purpose="CRM assistance and pipeline updates",
             environment="production", tools=["Salesforce", "Internal DB"],
             capabilities=["crm:read"], risk_level="high"),
        dict(id="agt_support", name="Support Agent", owner="m.chen", purpose="Ticket triage and replies",
             environment="production", tools=["Zendesk"], capabilities=["support:read", "support:write"], risk_level="low"),
        dict(id="agt_ops", name="Ops Agent", owner=None, purpose="Production record maintenance",
             environment="production", tools=["Internal DB"], capabilities=["db:read"], risk_level="medium"),
        dict(id="agt_finance", name="Finance Agent", owner="a.okafor", purpose="Invoice reading and reconciliation",
             environment="production", tools=["ERP"], capabilities=["erp:read"], risk_level="medium"),
        dict(id="agt_marketing", name="Marketing Agent", owner="s.patel", purpose="Campaign reporting",
             environment="production", tools=["Google Ads"], capabilities=["ads:read"], risk_level="medium"),
    ]
    for a in agents:
        try:
            services.register_agent(TENANT, a)
        except Exception:
            pass  # already seeded

    policies = [
        dict(id="pol_export", name="No bulk customer-data export", priority=10, effect="deny",
             match_field="capability", match_pattern="pii:export",
             reason="Bulk PII export exceeds permitted scope for any agent"),
        dict(id="pol_prod_delete", name="No deletions without approval", priority=20, effect="require_approval",
             match_field="capability", match_pattern="data:delete",
             reason="Destructive action requires human authorization"),
        dict(id="pol_prod_write", name="Production writes need approval", priority=30, effect="require_approval",
             match_field="capability", match_pattern="prod:write",
             reason="Production mutation requires human authorization"),
        dict(id="pol_ops_scope", name="Ops agent restricted to db reads", priority=15, effect="deny",
             match_field="agent_id", match_pattern="agt_ops", context_field="capability", context_pattern="db:write",
             reason="Ops Agent has read-only grant; write attempted outside scope"),
        dict(id="pol_ads_bulk", name="Ads bulk exports blocked", priority=40, effect="deny",
             match_field="api_call", match_pattern="ads.bulk_export",
             reason="Bulk ad-platform exports are out of policy"),
        dict(id="pol_sensitive_read", name="Sensitive finance reads allowed", priority=90, effect="allow",
             match_field="resource", match_pattern="sensitive/*",
             reason="Read-only access to finance records is permitted"),
    ]
    for p in policies:
        p.setdefault("enabled", True)
        p.setdefault("reason", "")
        services.upsert_policy(TENANT, p)

    # A realistic day of activity: (agent, tool, api_call, args, user_request)
    actions = [
        ("agt_sales", "Salesforce", "crm.read_contacts", {"filter": "stage=closed"}, "Show my closed deals this week"),
        ("agt_support", "Zendesk", "zendesk.get_ticket", {"id": "T-8841"}, "Summarize open tickets"),
        ("agt_ops", "Internal DB", "internal_db.read", {"table": "deployments"}, "Check last deployment status"),
        ("agt_finance", "ERP", "erp.read_invoice", {"id": "INV-2201"}, "Read invoice INV-2201"),
        ("agt_marketing", "Google Ads", "ads.read_report", {"campaign": "q4"}, "Pull Q4 campaign report"),
        ("agt_sales", "Salesforce", "crm.export_customers", {"scope": "all", "format": "csv"}, "Export all customers"),
        ("agt_ops", "Internal DB", "internal_db.update_production_record", {"table": "orders", "id": "o-991"}, "Fix order total"),
        ("agt_finance", "ERP", "erp.read_invoice", {"id": "INV-2202"}, "Read invoice INV-2202"),
        ("agt_marketing", "Google Ads", "ads.bulk_export", {"scope": "all"}, "Bulk export ad data"),
        ("agt_support", "Zendesk", "zendesk.reply_ticket", {"id": "T-8841"}, "Send canned reply"),
        ("agt_sales", "Salesforce", "crm.delete_records", {"scope": "old"}, "Delete old records"),
        ("agt_finance", "ERP", "erp.write_journal", {"entry": "adj-14"}, "Post adjustment"),
        ("agt_support", "Zendesk", "zendesk.get_ticket", {"id": "T-8842"}, "Summarize ticket"),
        ("agt_sales", "Salesforce", "crm.read_record", {"id": "acc-77"}, "Look up account 77"),
    ]
    for agent, tool, call, args, req in actions:
        services.record_action(TENANT, agent, tool, call, args=args, user_request=req)

    print("seeded:", TENANT)


if __name__ == "__main__":
    seed()
