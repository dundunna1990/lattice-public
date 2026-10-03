"""Fleet-wide verification and guarded clearing of proven-resolved state."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.core.http_client import LatticeHTTPClient
from lattice.care.observations import normalize_care_observation
from lattice.verification.alerts import evaluate_active_alerts
from lattice.verification.node import (
    VerificationError,
    clear_local_resolved_state,
    collect_local_verification,
)


class FleetVerificationError(RuntimeError):
    pass


def _membership_snapshot() -> tuple[int, list[dict]]:
    conn = get_db_connection()
    try:
        state = conn.execute("SELECT generation FROM fleet_state WHERE id=1").fetchone()
        generation = int(state["generation"]) if state is not None else 0
        rows = conn.execute(
            """SELECT fn.node_id,fn.hostname,fn.role,fn.worker_id,
                      w.ip,w.status AS worker_status
               FROM fleet_nodes fn
               LEFT JOIN workers w ON w.id=fn.worker_id
               WHERE fn.membership_state='active'
               ORDER BY CASE fn.role WHEN 'master' THEN 0 ELSE 1 END, fn.hostname"""
        ).fetchall()
        return generation, [dict(row) for row in rows]
    finally:
        conn.close()


async def _worker_verification(member: dict) -> dict:
    hostname = str(member["hostname"])
    ip = str(member.get("ip") or "")
    if not ip:
        return {
            "node_id": member["node_id"],
            "hostname": hostname,
            "role": "worker",
            "status": "blocked",
            "blockers": ["active Worker has no current IP address"],
            "stale_failed_units": [],
            "blocking_failed_units": [],
            "network_state": "unknown",
        }
    client = LatticeHTTPClient(worker_hostname=hostname)
    try:
        port = load_config().wire_format.port
        response = await client.get(f"http://{ip}:{port}/v1/verification", timeout=8.0)
        payload = response.json()
        if response.status_code != 200 or not isinstance(payload, dict):
            raise FleetVerificationError("Worker verification response is invalid")
        if payload.get("node_id") != member["node_id"]:
            raise FleetVerificationError("authenticated Worker Node ID does not match active membership")
        if payload.get("hostname") != hostname:
            raise FleetVerificationError("authenticated Worker hostname does not match active membership")
        return payload
    except Exception as exc:
        return {
            "node_id": member["node_id"],
            "hostname": hostname,
            "role": "worker",
            "status": "blocked",
            "blockers": [f"authenticated live verification failed: {exc}"],
            "stale_failed_units": [],
            "blocking_failed_units": [],
            "network_state": "unknown",
        }
    finally:
        await client.aclose()


async def _collect_fleet() -> tuple[int, list[dict]]:
    generation, members = _membership_snapshot()
    masters = [item for item in members if item["role"] == "master"]
    if len(masters) != 1:
        raise FleetVerificationError("active fleet must contain exactly one Master")

    master = collect_local_verification("master")
    if master["node_id"] != masters[0]["node_id"]:
        raise FleetVerificationError("local Master identity does not match active membership")
    workers = [item for item in members if item["role"] == "worker"]
    remote = await asyncio.gather(*(_worker_verification(item) for item in workers))
    reports = [master, *remote]
    expected = {str(item["node_id"]) for item in members}
    observed = {str(item.get("node_id") or "") for item in reports}
    if expected != observed:
        raise FleetVerificationError("verification did not account for every active fleet member")
    return generation, reports


def verify_fleet() -> dict:
    """Verify every active fleet member and every active alert without mutating state."""
    try:
        generation, nodes = asyncio.run(_collect_fleet())
    except Exception as exc:
        return {
            "status": "blocked",
            "can_clear": False,
            "fleet_generation": None,
            "nodes": [],
            "alerts": [],
            "blockers": [str(exc)],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    reports = {str(item["hostname"]): item for item in nodes}
    alerts = evaluate_active_alerts(reports)
    blockers: list[str] = []
    for node in nodes:
        for reason in node.get("blockers", []):
            blockers.append(f"{node['hostname']}: {reason}")
    for alert in alerts:
        if alert["verdict"] != "resolved":
            blockers.append(f"{alert['title']}: {alert['reason']}")
    candidates = [item for item in alerts if item["verdict"] == "resolved"]
    stale_units = sum(len(item.get("stale_failed_units", [])) for item in nodes)
    stale_care = sum(
        1 for item in nodes
        if str(dict(item.get("stored_care") or {}).get("status") or "stale")
        not in {"healthy", "off"}
    )
    status = "pass" if not blockers else "blocked"
    return {
        "status": status,
        "can_clear": status == "pass" and bool(candidates or stale_units or stale_care),
        "fleet_generation": generation,
        "nodes": nodes,
        "alerts": alerts,
        "resolved_alert_ids": [item["id"] for item in candidates],
        "stale_failed_unit_count": stale_units,
        "stale_care_count": stale_care,
        "blockers": blockers,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


async def _clear_workers(members: list[dict]) -> list[dict]:
    if not members:
        return []
    return list(await asyncio.gather(*(_clear_worker(item) for item in members)))


async def _clear_worker(member: dict) -> dict:
    hostname = str(member["hostname"])
    ip = str(member.get("ip") or "")
    if not ip:
        raise FleetVerificationError(f"{hostname} has no current IP address")
    client = LatticeHTTPClient(worker_hostname=hostname)
    try:
        port = load_config().wire_format.port
        response = await client.post(f"http://{ip}:{port}/v1/verification/clear", timeout=20.0)
        payload = response.json()
        if response.status_code != 200 or not isinstance(payload, dict):
            raise FleetVerificationError(f"{hostname} refused resolved-state clearing")
        return payload
    finally:
        await client.aclose()


def _refresh_replicated_care(nodes: list[dict]) -> None:
    """Apply authenticated Worker care snapshots immediately after a clear."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for node in nodes:
            if node.get("role") != "worker":
                continue
            node_id = str(node.get("node_id") or "")
            raw = node.get("stored_care")
            if not node_id or not isinstance(raw, dict):
                raise FleetVerificationError("Worker care verification evidence is incomplete")
            care = normalize_care_observation(raw, node_id)
            conn.execute(
                """INSERT INTO care_observations(
                       node_id,hostname,status,last_run_at,bytes_reclaimed,
                       attention_count,critical_count,deferred_reason,findings_json,last_reported_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(node_id) DO UPDATE SET
                     hostname=excluded.hostname,status=excluded.status,
                     last_run_at=excluded.last_run_at,bytes_reclaimed=excluded.bytes_reclaimed,
                     attention_count=excluded.attention_count,critical_count=excluded.critical_count,
                     deferred_reason=excluded.deferred_reason,findings_json=excluded.findings_json,
                     last_reported_at=excluded.last_reported_at""",
                (
                    node_id, str(care.get("hostname") or node.get("hostname") or "unknown")[:255],
                    care["status"], care.get("last_run_at"), care["bytes_reclaimed"],
                    care["attention_count"], care["critical_count"], care.get("deferred_reason"),
                    json.dumps(care.get("findings", []), sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _resolve_verified_alerts(report: dict) -> int:
    candidates = {int(item["id"]): item for item in report["alerts"] if item["verdict"] == "resolved"}
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            """SELECT a.id,a.worker_id,a.title FROM alerts a
               WHERE a.resolved_at IS NULL ORDER BY a.id"""
        ).fetchall()
        for row in active:
            if int(row["id"]) not in candidates:
                conn.rollback()
                raise FleetVerificationError("active alert set changed before clear; verify again")
        now = datetime.now(timezone.utc).isoformat()
        resolved = 0
        for row in active:
            item = candidates[int(row["id"])]
            event = conn.execute(
                """INSERT INTO events(timestamp,worker_id,type,severity,message,details)
                   VALUES(?,?,'verification.recovered','ok',?,?)""",
                (
                    now,
                    row["worker_id"],
                    f"Fleet verification proved resolved: {row['title']}",
                    json.dumps({
                        "alert_id": int(row["id"]),
                        "event_type": item["event_type"],
                        "reason": item["reason"],
                    }, sort_keys=True),
                ),
            )
            cursor = conn.execute(
                """UPDATE alerts SET resolved_at=?,resolution_event_id=?
                   WHERE id=? AND resolved_at IS NULL""",
                (now, int(event.lastrowid), int(row["id"])),
            )
            resolved += int(cursor.rowcount)
        conn.commit()
        return resolved
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def clear_proven_resolved() -> dict:
    """Reverify the current fleet, then clear only state proven recovered."""
    first = verify_fleet()
    if first["status"] != "pass":
        return {**first, "clear_status": "blocked", "cleared_alerts": 0}

    generation, members = _membership_snapshot()
    current_ids = {str(item["node_id"]) for item in members}
    verified_ids = {str(item.get("node_id") or "") for item in first.get("nodes", [])}
    if generation != first["fleet_generation"] or current_ids != verified_ids:
        return {
            **first,
            "clear_status": "blocked",
            "blockers": ["active fleet membership changed; verify again"],
        }
    workers = [item for item in members if item["role"] == "worker"]
    remote_results: list[dict] = []
    try:
        if workers:
            remote_results = asyncio.run(_clear_workers(workers))
        local_result = clear_local_resolved_state("master")
    except Exception as exc:
        return {
            **first,
            "clear_status": "blocked",
            "cleared_alerts": 0,
            "blockers": [f"resolved-state clear stopped safely: {exc}"],
        }

    second = verify_fleet()
    second_membership_changed = (
        second.get("fleet_generation") != first.get("fleet_generation")
        or {str(item.get("node_id") or "") for item in second.get("nodes", [])} != verified_ids
    )
    if second["status"] != "pass" or second_membership_changed:
        blockers = list(second.get("blockers") or [])
        if second_membership_changed:
            blockers.append("active fleet membership changed during clear; verify again")
        return {
            **second,
            "clear_status": "blocked",
            "cleared_alerts": 0,
            "blockers": blockers,
            "local_clear": local_result,
            "worker_clears": remote_results,
        }
    try:
        _refresh_replicated_care(second.get("nodes", []))
        cleared = _resolve_verified_alerts(second)
    except Exception as exc:
        return {
            **second,
            "clear_status": "blocked",
            "cleared_alerts": 0,
            "blockers": [f"alert clear stopped safely: {exc}"],
            "local_clear": local_result,
            "worker_clears": remote_results,
        }

    final = verify_fleet()
    return {
        **final,
        "clear_status": "cleared" if final["status"] == "pass" else "changed_after_clear",
        "cleared_alerts": cleared,
        "local_clear": local_result,
        "worker_clears": remote_results,
    }
