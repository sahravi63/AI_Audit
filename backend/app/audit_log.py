"""Append-only, hash-chained audit log.

Every record stores prev_hash and hash = SHA-256(seq|ts|kind|payload|prev_hash).
Genesis uses prev_hash 'GENESIS'. Verification recomputes the whole chain and
checks payload digests, so any tampering (edit, delete, reorder) is detectable.
Exports embed the chain so third parties can verify integrity offline.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from . import db


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest_record(seq: int, ts: str, kind: str, payload: str, prev_hash: str) -> str:
    material = f"{seq}|{ts}|{kind}|{payload}|{prev_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def append(conn, kind: str, payload: dict) -> dict:
    """Append one record. Must be called inside a db.tx() block."""
    row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else "GENESIS"
    ts = now_iso()
    payload_str = canonical_json(payload)
    next_seq = conn.execute("SELECT COALESCE(MAX(seq),0)+1 n FROM audit_log").fetchone()["n"]
    h = digest_record(next_seq, ts, kind, payload_str, prev_hash)
    conn.execute(
        "INSERT INTO audit_log (seq, ts, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)",
        (next_seq, ts, kind, payload_str, prev_hash, h),
    )
    return {"seq": next_seq, "ts": ts, "kind": kind, "payload": payload, "prev_hash": prev_hash, "hash": h}


def verify_chain(conn) -> dict:
    rows = db.rows_to_dicts(conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall())
    prev = "GENESIS"
    for r in rows:
        expected = digest_record(r["seq"], r["ts"], r["kind"], r["payload"], prev)
        if r["prev_hash"] != prev:
            return {"valid": False, "checked": len(rows), "broken_at_seq": r["seq"], "error": "prev_hash mismatch (record inserted or removed)"}
        if r["hash"] != expected:
            return {"valid": False, "checked": len(rows), "broken_at_seq": r["seq"], "error": "hash mismatch (record altered)"}
        prev = r["hash"]
    return {"valid": True, "checked": len(rows), "head": prev, "error": None, "broken_at_seq": None}


def all_records(conn) -> list[dict]:
    rows = db.rows_to_dicts(conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall())
    for r in rows:
        r["payload"] = json.loads(r["payload"])
    return rows
