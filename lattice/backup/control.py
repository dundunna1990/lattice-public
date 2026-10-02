"""Restricted root/operator control plane for human backup actions."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys

from lattice.backup.jobs import (
    BackupJobError,
    create_home_backup_job,
    register_discovered_target,
    set_job_paused,
)
from lattice.backup.manual import ManualBackupError, queue_manual_backup
from lattice.backup.query import (
    BackupQueryError,
    queue_backup_query,
    wait_for_query_result,
)
from lattice.backup.restore_request import (
    BackupRestoreRequestError,
    queue_restore_request,
    wait_for_restore_result,
)
from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.core.http_client import LatticeHTTPClient
from lattice.core.events import log_event
from lattice.file_access.identity import load_node_identity


class BackupControlError(RuntimeError):
    pass


def _positive_int(value: str, label: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise BackupControlError(f"{label} is invalid") from exc
    if parsed < 1:
        raise BackupControlError(f"{label} must be positive")
    return parsed


def setup_backup(source_node_id: str, target_kind: str, target_ref: str, friendly_name: str) -> dict:
    if target_kind not in {"target", "candidate"}:
        raise BackupControlError("Backup destination type is invalid")
    if not isinstance(friendly_name, str) or not friendly_name.strip() or len(friendly_name) > 100:
        raise BackupControlError("Backup destination name is invalid")
    created_target = None
    try:
        if target_kind == "candidate":
            if not re.fullmatch(r"[0-9a-f]{20}", target_ref):
                raise BackupControlError("Detected backup drive selection is invalid")
            created_target = register_discovered_target(
                target_ref,
                friendly_name=friendly_name.strip(),
            )
            target_id = int(created_target["id"])
        else:
            target_id = _positive_int(target_ref, "Backup target ID")
            conn = get_db_connection()
            try:
                row = conn.execute(
                    "SELECT id,friendly_name FROM backup_targets WHERE id=? AND enabled=1",
                    (target_id,),
                ).fetchone()
            finally:
                conn.close()
            if row is None:
                raise BackupControlError("Backup target is unavailable")
        job = create_home_backup_job(source_node_id=source_node_id, target_id=target_id)
        return {
            "status": "created",
            "job_uuid": job["job_uuid"],
            "job_id": int(job["id"]),
            "target_id": target_id,
        }
    except BackupJobError as exc:
        # If this invocation created a brand-new target but the job could not
        # be created, disable that orphan rather than leaving it selectable.
        if created_target is not None:
            conn = get_db_connection()
            try:
                conn.execute(
                    "UPDATE backup_targets SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (int(created_target["id"]),),
                )
                conn.commit()
            finally:
                conn.close()
        raise BackupControlError(str(exc)) from exc


def pause_backup(job_id: int, reason: str) -> dict:
    try:
        row = set_job_paused(job_id, paused=True, reason=reason)
    except BackupJobError as exc:
        raise BackupControlError(str(exc)) from exc
    return {"status": "paused", "job_id": int(row["id"])}


def resume_backup(job_id: int) -> dict:
    try:
        row = set_job_paused(job_id, paused=False)
    except BackupJobError as exc:
        raise BackupControlError(str(exc)) from exc
    return {"status": "active", "job_id": int(row["id"])}


def _manual_job(job_uuid: str, *, require_active: bool = True) -> dict:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.job_uuid,bj.source_node_id,bj.enabled,bj.paused,
                      fn.hostname,fn.worker_id,w.ip,bt.friendly_name AS target_name,
                      bt.enabled AS target_enabled
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               LEFT JOIN workers w ON w.id=fn.worker_id
               WHERE bj.job_uuid=?""",
            (job_uuid,),
        ).fetchone()
        if row is None:
            raise BackupControlError("Backup job was not found")
        data = dict(row)
    finally:
        conn.close()
    if not bool(data["enabled"]) or not bool(data["target_enabled"]):
        raise BackupControlError("Backup job is unavailable")
    if require_active and bool(data["paused"]):
        raise BackupControlError("Paused backup must be resumed before running it now")
    return data


def _log_restore_event(job: dict, event_type: str, severity: str, message: str, details: dict | None = None) -> None:
    try:
        log_event(
            int(job["worker_id"]) if job.get("worker_id") is not None else None,
            event_type,
            severity,
            message,
            {
                "job_uuid": str(job["job_uuid"]),
                "source": str(job["hostname"]),
                "target": str(job.get("target_name") or ""),
                **(details or {}),
            },
        )
    except Exception:
        # Event logging is observability only; it must never turn a completed
        # restore into an apparent restore failure.
        pass


async def _request_worker_run(
    job: dict,
    *,
    full_speed: bool = False,
    allow_large_first_backup: bool = False,
) -> dict:
    hostname = str(job["hostname"])
    ip = str(job.get("ip") or "").strip()
    if not ip:
        raise BackupControlError(f"No current worker API address is known for {hostname}")
    config = load_config()
    port = int(getattr(config.wire_format, "port", 9999))
    client = LatticeHTTPClient(worker_hostname=hostname)
    try:
        response = await client.post(
            f"http://{ip}:{port}/v1/backups/run",
            json={
                "job_uuid": job["job_uuid"],
                "full_speed": full_speed,
                "allow_large_first_backup": allow_large_first_backup,
            },
            timeout=15.0,
        )
        if response.status_code not in {200, 202}:
            detail = ""
            try:
                detail = str(response.json().get("detail") or "")
            except Exception:
                detail = response.text[:500]
            raise BackupControlError(
                f"{hostname} refused the backup request: {detail or response.status_code}"
            )
        payload = response.json()
        return payload if isinstance(payload, dict) else {"status": "accepted"}
    except BackupControlError:
        raise
    except Exception as exc:
        raise BackupControlError(f"Could not reach {hostname} to start its backup: {exc}") from exc
    finally:
        await client.aclose()


async def _request_worker_query(
    job: dict,
    operation: str,
    *,
    snapshot_id: str | None = None,
    directory: str | None = None,
) -> dict:
    hostname = str(job["hostname"])
    ip = str(job.get("ip") or "").strip()
    if not ip:
        raise BackupControlError(f"No current worker API address is known for {hostname}")
    config = load_config()
    port = int(getattr(config.wire_format, "port", 9999))
    client = LatticeHTTPClient(worker_hostname=hostname)
    try:
        response = await client.post(
            f"http://{ip}:{port}/v1/backups/query",
            json={
                "job_uuid": job["job_uuid"],
                "operation": operation,
                "snapshot_id": snapshot_id,
                "directory": directory,
            },
            timeout=15.0,
        )
        if response.status_code not in {200, 202}:
            try:
                detail = str(response.json().get("detail") or "")
            except Exception:
                detail = response.text[:500]
            raise BackupControlError(
                f"{hostname} refused the backup browse request: {detail or response.status_code}"
            )
        payload = response.json()
        request_id = payload.get("request_id") if isinstance(payload, dict) else None
        if not isinstance(request_id, str):
            raise BackupControlError(f"{hostname} returned an invalid backup browse request ID")
        poll_attempts = 1500 if operation == "recovery_preflight" else 150
        for _ in range(poll_attempts):
            await asyncio.sleep(0.2)
            result_response = await client.get(
                f"http://{ip}:{port}/v1/backups/query-result/{request_id}",
                timeout=10.0,
            )
            result = result_response.json()
            if not isinstance(result, dict):
                raise BackupControlError(f"{hostname} returned an invalid backup browse result")
            if result.get("status") == "pending":
                continue
            if result.get("status") == "failed":
                raise BackupControlError(str(result.get("error") or "Backup browse failed"))
            if result.get("status") == "successful":
                return result
            raise BackupControlError(f"{hostname} returned an unknown backup browse status")
        raise BackupControlError(f"Timed out waiting for {hostname} to browse its backup")
    except BackupControlError:
        raise
    except Exception as exc:
        raise BackupControlError(f"Could not browse backup on {hostname}: {exc}") from exc
    finally:
        await client.aclose()


def query_backup(
    job_uuid: str,
    operation: str,
    *,
    snapshot_id: str | None = None,
    directory: str | None = None,
) -> dict:
    if operation not in {"snapshots", "directory", "recovery_preflight"}:
        raise BackupControlError("Backup query operation is invalid")
    job = _manual_job(job_uuid, require_active=False)
    identity = load_node_identity()
    if identity is None:
        raise BackupControlError("Local Lattice node identity is unavailable")
    if job["source_node_id"] == identity.node_id:
        try:
            request_id = queue_backup_query(
                job_uuid,
                operation,
                snapshot_id=snapshot_id,
                directory=directory,
            )
            result = wait_for_query_result(
                request_id,
                timeout_seconds=300.0 if operation == "recovery_preflight" else 30.0,
            )
        except BackupQueryError as exc:
            raise BackupControlError(str(exc)) from exc
    else:
        if job.get("worker_id") is None:
            raise BackupControlError("Backup source is not a reachable Lattice worker")
        result = asyncio.run(
            _request_worker_query(
                job,
                operation,
                snapshot_id=snapshot_id,
                directory=directory,
            )
        )
    if result.get("status") != "successful":
        raise BackupControlError(str(result.get("error") or "Backup browse failed"))
    return result


async def _request_worker_restore(job: dict, payload: dict) -> dict:
    hostname = str(job["hostname"])
    ip = str(job.get("ip") or "").strip()
    if not ip:
        raise BackupControlError(f"No current worker API address is known for {hostname}")
    config = load_config()
    port = int(getattr(config.wire_format, "port", 9999))
    client = LatticeHTTPClient(worker_hostname=hostname)
    try:
        response = await client.post(
            f"http://{ip}:{port}/v1/backups/restore",
            json=payload,
            timeout=15.0,
        )
        if response.status_code not in {200, 202}:
            try:
                detail = str(response.json().get("detail") or "")
            except Exception:
                detail = response.text[:500]
            raise BackupControlError(
                f"{hostname} refused the restore request: {detail or response.status_code}"
            )
        accepted = response.json()
        request_id = accepted.get("request_id") if isinstance(accepted, dict) else None
        if not isinstance(request_id, str):
            raise BackupControlError(f"{hostname} returned an invalid restore request ID")
        for _ in range(2400):
            await asyncio.sleep(0.25)
            result_response = await client.get(
                f"http://{ip}:{port}/v1/backups/restore-result/{request_id}",
                timeout=10.0,
            )
            result = result_response.json()
            if not isinstance(result, dict):
                raise BackupControlError(f"{hostname} returned an invalid restore result")
            if result.get("status") == "pending":
                continue
            if result.get("status") == "failed":
                raise BackupControlError(str(result.get("error") or "Restore failed"))
            if result.get("status") == "successful":
                return result
            raise BackupControlError(f"{hostname} returned an unknown restore status")
        raise BackupControlError(f"Timed out waiting for {hostname} to complete restore work")
    except BackupControlError:
        raise
    except Exception as exc:
        raise BackupControlError(f"Could not perform restore on {hostname}: {exc}") from exc
    finally:
        await client.aclose()


def restore_backup(
    job_uuid: str,
    operation: str,
    *,
    snapshot_id: str | None = None,
    selection: str | None = None,
    session_uuid: str | None = None,
    choice: str | None = None,
    elsewhere: str | None = None,
) -> dict:
    if operation not in {"stage", "place", "cancel"}:
        raise BackupControlError("Restore operation is invalid")
    job = _manual_job(job_uuid, require_active=False)
    payload = {
        "operation": operation,
        "job_uuid": job_uuid if operation == "stage" else None,
        "snapshot_id": snapshot_id,
        "selection": selection,
        "session_uuid": session_uuid,
        "choice": choice,
        "elsewhere": elsewhere,
    }
    identity = load_node_identity()
    if identity is None:
        raise BackupControlError("Local Lattice node identity is unavailable")
    if job["source_node_id"] == identity.node_id:
        try:
            request_id = queue_restore_request(
                operation,
                job_uuid=job_uuid if operation == "stage" else None,
                snapshot_id=snapshot_id,
                selection=selection,
                session_uuid=session_uuid,
                choice=choice,
                elsewhere=elsewhere,
            )
            result = wait_for_restore_result(request_id, timeout_seconds=600.0)
        except BackupRestoreRequestError as exc:
            raise BackupControlError(str(exc)) from exc
    else:
        if job.get("worker_id") is None:
            raise BackupControlError("Backup source is not a reachable Lattice worker")
        result = asyncio.run(_request_worker_restore(job, payload))
    if result.get("status") != "successful":
        raise BackupControlError(str(result.get("error") or "Restore failed"))
    if operation == "stage":
        _log_restore_event(
            job,
            "backup.restore_started",
            "info",
            f"Restore prepared: {job['hostname']} backup",
            {
                "snapshot_id": str(snapshot_id or "")[:128],
                "selection": str(selection or "")[:4096],
                "session_uuid": str(result.get("session_uuid") or "")[:36],
            },
        )
    elif operation == "place":
        _log_restore_event(
            job,
            "backup.restore_completed",
            "ok",
            f"Restore completed: {job['hostname']} backup",
            {
                "session_uuid": str(session_uuid or "")[:36],
                "choice": str(choice or "")[:32],
                "destination": str(result.get("destination") or "")[:4096],
            },
        )
    return result


def run_backup_now(
    job_uuid: str,
    *,
    full_speed: bool = False,
    allow_large_first_backup: bool = False,
) -> dict:
    if not isinstance(full_speed, bool):
        raise BackupControlError("Full Speed override must be boolean")
    if not isinstance(allow_large_first_backup, bool):
        raise BackupControlError("Large Backup confirmation must be boolean")
    job = _manual_job(job_uuid)
    identity = load_node_identity()
    if identity is None:
        raise BackupControlError("Local Lattice node identity is unavailable")
    if job["source_node_id"] == identity.node_id:
        try:
            queued = queue_manual_backup(
                job_uuid,
                full_speed=full_speed,
                allow_large_first_backup=allow_large_first_backup,
            )
        except ManualBackupError as exc:
            raise BackupControlError(str(exc)) from exc
        return {
            "status": "accepted" if queued else "already_pending",
            "job_uuid": job_uuid,
            "source": job["hostname"],
        }
    if job.get("worker_id") is None:
        raise BackupControlError("Backup source is not a reachable Lattice worker")
    result = asyncio.run(
        _request_worker_run(
            job,
            full_speed=full_speed,
            allow_large_first_backup=allow_large_first_backup,
        )
    )
    return {
        "status": result.get("status", "accepted"),
        "job_uuid": job_uuid,
        "source": job["hostname"],
    }


def main(argv: list[str] | None = None) -> None:
    if os.geteuid() != 0:
        raise SystemExit("REFUSED: lattice-backup-control must run as root")
    parser = argparse.ArgumentParser(prog="lattice-backup-control")
    sub = parser.add_subparsers(dest="action", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("source_node_id")
    setup.add_argument("target_kind", choices=["target", "candidate"])
    setup.add_argument("target_ref")
    setup.add_argument("friendly_name")
    pause = sub.add_parser("pause")
    pause.add_argument("job_id")
    pause.add_argument("reason")
    resume = sub.add_parser("resume")
    resume.add_argument("job_id")
    run = sub.add_parser("run-now")
    run.add_argument("job_uuid")
    run.add_argument("--full-speed", action="store_true")
    run.add_argument("--confirm-large-backup", action="store_true")
    snapshots = sub.add_parser("snapshots")
    snapshots.add_argument("job_uuid")
    browse = sub.add_parser("browse")
    browse.add_argument("job_uuid")
    browse.add_argument("snapshot_id")
    browse.add_argument("directory")
    recovery_preflight = sub.add_parser("recovery-preflight")
    recovery_preflight.add_argument("job_uuid")
    recovery_preflight.add_argument("snapshot_id")
    restore_stage = sub.add_parser("restore-stage")
    restore_stage.add_argument("job_uuid")
    restore_stage.add_argument("snapshot_id")
    restore_stage.add_argument("selection")
    restore_place = sub.add_parser("restore-place")
    restore_place.add_argument("job_uuid")
    restore_place.add_argument("session_uuid")
    restore_place.add_argument("choice", choices=["keep_both", "replace", "elsewhere"])
    restore_place.add_argument("elsewhere", nargs="?")
    restore_cancel = sub.add_parser("restore-cancel")
    restore_cancel.add_argument("job_uuid")
    restore_cancel.add_argument("session_uuid")
    args = parser.parse_args(argv)
    try:
        if args.action == "setup":
            result = setup_backup(args.source_node_id, args.target_kind, args.target_ref, args.friendly_name)
        elif args.action == "pause":
            result = pause_backup(_positive_int(args.job_id, "Backup job ID"), args.reason)
        elif args.action == "resume":
            result = resume_backup(_positive_int(args.job_id, "Backup job ID"))
        elif args.action == "run-now":
            result = run_backup_now(
                args.job_uuid,
                full_speed=args.full_speed,
                allow_large_first_backup=args.confirm_large_backup,
            )
        elif args.action == "snapshots":
            result = query_backup(args.job_uuid, "snapshots")
        elif args.action == "browse":
            result = query_backup(
                args.job_uuid,
                "directory",
                snapshot_id=args.snapshot_id,
                directory=args.directory,
            )
        elif args.action == "recovery-preflight":
            result = query_backup(
                args.job_uuid,
                "recovery_preflight",
                snapshot_id=args.snapshot_id,
            )
        elif args.action == "restore-stage":
            result = restore_backup(
                args.job_uuid,
                "stage",
                snapshot_id=args.snapshot_id,
                selection=args.selection,
            )
        elif args.action == "restore-place":
            result = restore_backup(
                args.job_uuid,
                "place",
                session_uuid=args.session_uuid,
                choice=args.choice,
                elsewhere=args.elsewhere,
            )
        else:
            result = restore_backup(
                args.job_uuid,
                "cancel",
                session_uuid=args.session_uuid,
            )
    except BackupControlError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        raise SystemExit(2)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("Unexpected Backup control failure")
        print(json.dumps({
            "status": "error",
            "message": "Backup action could not be completed safely. No backup was created.",
        }))
        raise SystemExit(3) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
