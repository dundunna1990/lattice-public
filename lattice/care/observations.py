"""Local and replicated Daily Care observations."""

from __future__ import annotations

import socket
import sqlite3
from datetime import datetime, timezone

from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

CARE_STALE_SECONDS = 36 * 60 * 60
VALID_STATUS = {"healthy", "attention", "critical", "stale", "off"}


def local_care_observation(*, node_id: str | None = None) -> dict:
    if node_id is None:
        try:
            identity = load_node_identity()
            node_id = identity.node_id if identity else None
        except Exception:
            node_id = None
    stale = {
        "node_id": node_id,
        "hostname": socket.gethostname(),
        "status": "stale",
        "last_run_at": None,
        "bytes_reclaimed": 0,
        "attention_count": 0,
        "critical_count": 0,
        "findings": [],
    }
    conn = get_db_connection()
    try:
        try:
            run = conn.execute("SELECT * FROM care_runs ORDER BY id DESC LIMIT 1").fetchone()
            findings = conn.execute(
                "SELECT severity,code,subject,detail FROM care_findings "
                "WHERE cleared_at IS NULL "
                "ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, id DESC "
                "LIMIT 32"
            ).fetchall()
        except sqlite3.OperationalError:
            return stale
    finally:
        conn.close()
    if run is None:
        return stale
    result = dict(run)
    return {
        "node_id": node_id,
        "hostname": socket.gethostname(),
        "status": str(result["status"]),
        "last_run_at": result["finished_at"] or result["started_at"],
        "bytes_reclaimed": int(result["bytes_reclaimed"] or 0),
        "attention_count": int(result["attention_count"] or 0),
        "critical_count": int(result["critical_count"] or 0),
        "deferred_reason": result["deferred_reason"],
        "findings": [dict(row) for row in findings],
    }


def normalize_care_observation(value: object, expected_node_id: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError("care_observation must be an object")
    allowed = {
        "node_id",
        "hostname",
        "status",
        "last_run_at",
        "bytes_reclaimed",
        "attention_count",
        "critical_count",
        "deferred_reason",
        "findings",
    }
    if set(value) - allowed:
        raise ValueError("care_observation contains unsupported fields")
    if value.get("node_id") != expected_node_id:
        raise ValueError("care_observation node identity mismatch")
    status = value.get("status")
    if status not in VALID_STATUS:
        raise ValueError("care_observation status is invalid")
    for key in ("bytes_reclaimed", "attention_count", "critical_count"):
        if (
            isinstance(value.get(key), bool)
            or not isinstance(value.get(key), int)
            or value.get(key) < 0
        ):
            raise ValueError(f"care_observation {key} is invalid")
    findings = value.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 32:
        raise ValueError("care_observation findings are invalid")
    clean = []
    for item in findings:
        if not isinstance(item, dict) or set(item) - {"severity", "code", "subject", "detail"}:
            raise ValueError("care finding is invalid")
        severity = item.get("severity")
        if severity not in {"attention", "critical"}:
            raise ValueError("care finding severity is invalid")
        clean.append(
            {k: str(item.get(k) or "")[:1000] for k in ("severity", "code", "subject", "detail")}
        )
    return {**value, "findings": clean}


def observation_is_stale(last_run_at: object, *, now: datetime | None = None) -> bool:
    if not isinstance(last_run_at, str) or not last_run_at:
        return True
    try:
        then = datetime.fromisoformat(last_run_at)
    except ValueError:
        return True
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age = (current.astimezone(timezone.utc) - then.astimezone(timezone.utc)).total_seconds()
    return age < -60 or age > CARE_STALE_SECONDS
