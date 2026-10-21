"""SQLite data access layer for AuditDex AI.

Schema is deliberately portable (TEXT/INTEGER only) so it can be lifted to
PostgreSQL later without semantic changes. The audit_log table is
append-only and hash-chained; the API layer never issues UPDATE/DELETE
against it.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("AUDITDEX_DB", Path(__file__).resolve().parent.parent / "auditdex.sqlite3"))


def connect() -> sqlite3.Connection:
    # isolation_level=None => autocommit; explicit transactions via db.tx()
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


import contextlib  # noqa: E402


@contextlib.contextmanager
def tx(conn):
    """Atomic BEGIN IMMEDIATE ... COMMIT block.

    Connections run in autocommit mode, so audit appends and their paired
    event writes commit or roll back together.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    owner TEXT,
    purpose TEXT,
    environment TEXT NOT NULL DEFAULT 'production',
    tools TEXT NOT NULL DEFAULT '[]',          -- JSON array of tool names
    capabilities TEXT NOT NULL DEFAULT '[]',  -- JSON array of granted actions
    risk_level TEXT NOT NULL DEFAULT 'low',   -- low | medium | high
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    effect TEXT NOT NULL,                     -- deny | require_approval | allow
    match_field TEXT NOT NULL,                -- agent_id | capability | resource | tool
    match_pattern TEXT NOT NULL,              -- exact or '*' wildcard
    context_field TEXT,                       -- optional second condition field
    context_pattern TEXT,                     -- optional second condition pattern
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS action_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    trace_id TEXT NOT NULL,                   -- user request -> agent decision chain
    agent_id TEXT NOT NULL,
    user_request TEXT,                        -- originating human/agent instruction
    tool TEXT NOT NULL,
    api_call TEXT NOT NULL,                   -- normalized call name e.g. crm.export_customers
    resource TEXT,
    args TEXT NOT NULL DEFAULT '{}',          -- JSON snapshot of arguments
    decision TEXT NOT NULL,                   -- allowed | blocked | pending_approval | approved | rejected
    policy_id TEXT,                           -- policy version that decided (id#version)
    evidence TEXT,                            -- why the decision was made
    policy_hash TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'enforce',     -- enforce | log_only
    source TEXT NOT NULL DEFAULT 'gateway',
    latency_ms REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    event_id TEXT NOT NULL REFERENCES action_events(id),
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    note TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,                       -- action | approval | policy | agent
    payload TEXT NOT NULL,                    -- canonical JSON record
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON action_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_trace ON action_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id, enabled, priority);
"""


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Forward-compatible migration for databases created by earlier demos.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(action_events)")}
        for name, declaration in (("policy_hash", "TEXT NOT NULL DEFAULT ''"),
                                  ("mode", "TEXT NOT NULL DEFAULT 'enforce'"),
                                  ("source", "TEXT NOT NULL DEFAULT 'gateway'")):
            if name not in columns:
                conn.execute(f"ALTER TABLE action_events ADD COLUMN {name} {declaration}")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def rows_to_dicts(rows) -> list[dict]:
    out = []
    for r in rows:
        d = dict(r)
        for key in ("tools", "capabilities", "args"):
            if key in d and isinstance(d[key], str):
                d[key] = json.loads(d[key])
        out.append(d)
    return out
