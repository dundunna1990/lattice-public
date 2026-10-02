"""Signed source-owned backup configuration distribution."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import uuid

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import DEFAULT_FLEET_SIGNING_DIR, validate_ed25519_public_key
from lattice.file_access.sync import get_cached_signed_manifest, load_pinned_fleet_bootstrap

SCHEMA_VERSION = 1
SIGNING_NAMESPACE = "lattice-backup-config"
SIGNING_IDENTITY = "lattice-fleet-master"


class BackupConfigStateError(RuntimeError):
    pass


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupConfigStateError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupConfigStateError(f"{label} must be UUIDv4")
    return str(parsed)


def normalize_config(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise BackupConfigStateError("Backup configuration has an invalid schema")
    fleet_id = _uuid4(payload.get("fleet_id"), "Fleet ID")
    generation = payload.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise BackupConfigStateError("Backup configuration generation must be positive")

    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise BackupConfigStateError("Backup policy is missing")
    clean_policy = {}
    for key, minimum, maximum in (
        ("schedule_hour", 0, 23),
        ("retention_daily", 1, 3650),
        ("retention_weekly", 1, 520),
        ("retention_monthly", 1, 120),
        ("free_space_reserve_percent", 5, 50),
        ("deep_verification_days", 1, 90),
        ("persistent_alert_seconds", 300, 604800),
        ("bandwidth_limit_kib", 0, 10_000_000),
    ):
        value = policy.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise BackupConfigStateError(f"Backup policy {key} is invalid")
        clean_policy[key] = value

    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list) or len(raw_targets) > 128:
        raise BackupConfigStateError("Backup targets must be a bounded list")
    targets = []
    seen_targets = set()
    for raw in raw_targets:
        if not isinstance(raw, dict):
            raise BackupConfigStateError("Backup target must be an object")
        target_uuid = _uuid4(raw.get("target_uuid"), "Backup target ID")
        host_node_id = _uuid4(raw.get("host_node_id"), "Backup target host Node ID")
        if target_uuid in seen_targets:
            raise BackupConfigStateError("Backup target is duplicated")
        seen_targets.add(target_uuid)
        name = raw.get("friendly_name")
        filesystem_uuid = raw.get("filesystem_uuid")
        relative = raw.get("repository_relative_path")
        legacy_root = raw.get("repository_root")
        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise BackupConfigStateError("Backup target name is invalid")
        if not isinstance(filesystem_uuid, str) or not filesystem_uuid.strip() or len(filesystem_uuid) > 128:
            raise BackupConfigStateError("Backup target filesystem UUID is invalid")
        if not isinstance(relative, str) or not relative.strip() or len(relative) > 512:
            raise BackupConfigStateError("Backup target repository folder is invalid")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise BackupConfigStateError("Backup target repository folder is unsafe")
        if not isinstance(legacy_root, str) or not legacy_root.startswith("/") or len(legacy_root) > 4096:
            raise BackupConfigStateError("Backup target legacy path is invalid")
        targets.append({
            "target_uuid": target_uuid,
            "friendly_name": name.strip(),
            "host_node_id": host_node_id,
            "filesystem_uuid": filesystem_uuid.strip(),
            "repository_relative_path": str(relative_path),
            "repository_root": legacy_root,
        })
    targets.sort(key=lambda value: value["target_uuid"])

    raw_jobs = payload.get("jobs")
    if not isinstance(raw_jobs, list) or len(raw_jobs) > 256:
        raise BackupConfigStateError("Backup jobs must be a bounded list")
    jobs = []
    seen_jobs = set()
    target_ids = {item["target_uuid"] for item in targets}
    for raw in raw_jobs:
        if not isinstance(raw, dict):
            raise BackupConfigStateError("Backup job must be an object")
        job_uuid = _uuid4(raw.get("job_uuid"), "Backup job ID")
        source_node_id = _uuid4(raw.get("source_node_id"), "Backup source Node ID")
        target_uuid = _uuid4(raw.get("target_uuid"), "Backup target ID")
        if target_uuid not in target_ids:
            raise BackupConfigStateError("Backup job references an unknown target")
        if job_uuid in seen_jobs:
            raise BackupConfigStateError("Backup job is duplicated")
        seen_jobs.add(job_uuid)
        source_path = raw.get("source_path")
        paused = raw.get("paused")
        pause_reason = raw.get("pause_reason")
        if not isinstance(source_path, str) or not source_path.startswith("/home/") or len(source_path) > 4096:
            raise BackupConfigStateError("Backup source path is invalid")
        if not isinstance(paused, bool):
            raise BackupConfigStateError("Backup pause state is invalid")
        if pause_reason is not None and (not isinstance(pause_reason, str) or len(pause_reason) > 500):
            raise BackupConfigStateError("Backup pause reason is invalid")
        if paused and not (pause_reason or "").strip():
            raise BackupConfigStateError("Paused backup requires a reason")
        jobs.append({
            "job_uuid": job_uuid,
            "source_node_id": source_node_id,
            "target_uuid": target_uuid,
            "source_path": source_path,
            "paused": paused,
            "pause_reason": pause_reason.strip() if isinstance(pause_reason, str) else None,
        })
    jobs.sort(key=lambda value: value["job_uuid"])
    return {
        "schema_version": SCHEMA_VERSION,
        "fleet_id": fleet_id,
        "generation": generation,
        "policy": clean_policy,
        "targets": targets,
        "jobs": jobs,
    }


def canonical_config_bytes(payload: object) -> bytes:
    return json.dumps(normalize_config(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_config(payload: object, signing_private_key: Path) -> str:
    message = canonical_config_bytes(payload)
    with tempfile.TemporaryDirectory(prefix="lattice-backup-config-sign-") as tmp:
        message_path = Path(tmp) / "config.json"
        message_path.write_bytes(message)
        try:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-q", "-f", str(signing_private_key), "-n", SIGNING_NAMESPACE, str(message_path)],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupConfigStateError(f"Could not sign backup configuration: {exc}") from exc
        if result.returncode != 0:
            raise BackupConfigStateError((result.stderr or result.stdout or "Could not sign backup configuration").strip())
        signature = Path(str(message_path) + ".sig").read_text(encoding="utf-8")
    return signature


def verify_config(payload: object, signature: str, signing_public_key: str) -> bool:
    public_key = validate_ed25519_public_key(signing_public_key)
    if not isinstance(signature, str) or "BEGIN SSH SIGNATURE" not in signature:
        raise BackupConfigStateError("Backup configuration signature is invalid")
    message = canonical_config_bytes(payload)
    with tempfile.TemporaryDirectory(prefix="lattice-backup-config-verify-") as tmp:
        root = Path(tmp)
        allowed = root / "allowed_signers"
        sig = root / "config.sig"
        allowed.write_text(f"{SIGNING_IDENTITY} {public_key}\n", encoding="utf-8")
        sig.write_text(signature, encoding="utf-8")
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-q", "-f", str(allowed), "-I", SIGNING_IDENTITY, "-n", SIGNING_NAMESPACE, "-s", str(sig)],
            input=message, capture_output=True, timeout=30,
        )
    return result.returncode == 0


def _desired_config(conn) -> tuple[list[dict], list[dict], dict]:
    target_rows = conn.execute(
        """SELECT target_uuid,friendly_name,host_node_id,filesystem_uuid,
                  repository_root,repository_relative_path
           FROM backup_targets WHERE enabled=1 ORDER BY target_uuid"""
    ).fetchall()
    targets = [dict(row) for row in target_rows]
    job_rows = conn.execute(
        """SELECT bj.job_uuid,bj.source_node_id,bt.target_uuid,bj.source_path,
                  bj.paused,bj.pause_reason
           FROM backup_jobs bj JOIN backup_targets bt ON bt.id=bj.target_id
           WHERE bj.enabled=1 AND bt.enabled=1 ORDER BY bj.job_uuid"""
    ).fetchall()
    jobs = []
    for row in job_rows:
        item = dict(row)
        item["paused"] = bool(item["paused"])
        jobs.append(item)
    backup = load_config().backup
    policy = {
        "schedule_hour": backup.schedule_hour,
        "retention_daily": backup.retention_daily,
        "retention_weekly": backup.retention_weekly,
        "retention_monthly": backup.retention_monthly,
        "free_space_reserve_percent": backup.free_space_reserve_percent,
        "deep_verification_days": backup.deep_verification_days,
        "persistent_alert_seconds": backup.persistent_alert_seconds,
        "bandwidth_limit_kib": backup.bandwidth_limit_kib,
    }
    return targets, jobs, policy


def reconcile_config_state(*, signing_private_key: Path | None = None) -> dict:
    key = signing_private_key or DEFAULT_FLEET_SIGNING_DIR / "fleet_signing_ed25519"
    conn = get_db_connection()
    try:
        fleet = conn.execute("SELECT fleet_id FROM fleet_state WHERE id=1").fetchone()
        if fleet is None:
            raise BackupConfigStateError("Fleet state is not initialized")
        targets, jobs, policy = _desired_config(conn)
        previous = conn.execute("SELECT generation,config,signature FROM backup_config_state WHERE id=1").fetchone()
        if previous is not None:
            old = normalize_config(json.loads(previous["config"]))
            if old["targets"] == targets and old["jobs"] == jobs and old["policy"] == policy:
                return {"config": old, "signature": str(previous["signature"])}
            generation = int(previous["generation"]) + 1
        else:
            generation = 1
        candidate = normalize_config({
            "schema_version": 1,
            "fleet_id": fleet["fleet_id"],
            "generation": generation,
            "policy": policy,
            "targets": targets,
            "jobs": jobs,
        })
        signature = sign_config(candidate, key)
        conn.execute(
            """INSERT INTO backup_config_state(id,generation,config,signature) VALUES(1,?,?,?)
               ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,
                 config=excluded.config,signature=excluded.signature,updated_at=CURRENT_TIMESTAMP""",
            (generation, json.dumps(candidate, sort_keys=True, separators=(",", ":")), signature),
        )
        conn.commit()
        return {"config": candidate, "signature": signature}
    finally:
        conn.close()


def current_config_state() -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT config,signature FROM backup_config_state WHERE id=1").fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"config": normalize_config(json.loads(row["config"])), "signature": str(row["signature"])}


def runtime_policy() -> dict:
    """Return signed local runtime policy when present, otherwise local defaults."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT schedule_hour,retention_daily,retention_weekly,
                      retention_monthly,free_space_reserve_percent,
                      deep_verification_days,persistent_alert_seconds,bandwidth_limit_kib
               FROM backup_runtime_policy WHERE id=1"""
        ).fetchone()
    finally:
        conn.close()
    if row is not None:
        return dict(row)
    backup = load_config().backup
    return {
        "schedule_hour": backup.schedule_hour,
        "retention_daily": backup.retention_daily,
        "retention_weekly": backup.retention_weekly,
        "retention_monthly": backup.retention_monthly,
        "free_space_reserve_percent": backup.free_space_reserve_percent,
        "deep_verification_days": backup.deep_verification_days,
        "persistent_alert_seconds": backup.persistent_alert_seconds,
        "bandwidth_limit_kib": backup.bandwidth_limit_kib,
    }


def applied_config_generation() -> int:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT generation FROM backup_config_applied_state WHERE id=1").fetchone()
        return int(row["generation"]) if row is not None else 0
    finally:
        conn.close()


def _materialize_signed_fleet_references(conn, identity, config: dict) -> None:
    """Populate missing Worker-local fleet references from the trusted manifest."""
    required_node_ids = {
        str(item["host_node_id"]) for item in config["targets"]
    } | {
        str(item["source_node_id"]) for item in config["jobs"]
    }
    if required_node_ids:
        placeholders = ",".join("?" for _ in required_node_ids)
        present = {
            str(row[0])
            for row in conn.execute(
                f"SELECT node_id FROM fleet_nodes WHERE node_id IN ({placeholders})",
                tuple(sorted(required_node_ids)),
            ).fetchall()
        }
        if required_node_ids <= present:
            return

    cached = get_cached_signed_manifest()
    if cached is None:
        raise BackupConfigStateError("Trusted fleet manifest is unavailable")
    manifest, _signature = cached
    generation = int(manifest.get("generation", 0))
    for member in manifest.get("members", []):
        node_id = str(member["node_id"])
        if node_id == identity.node_id:
            main_uid = int(identity.main_uid)
            main_gid = int(identity.main_gid)
        else:
            # UID/GID are host-local and are not carried in the signed manifest.
            # -1 means unknown on this machine; Backup only needs the trusted
            # Node ID/main-user membership reference for its local foreign keys.
            main_uid = -1
            main_gid = -1
        conn.execute(
            """INSERT INTO fleet_nodes(
                   node_id,hostname,role,main_user,main_uid,main_gid,
                   membership_state,membership_generation)
               VALUES(?,?,?,?,?,?, 'active',?)
               ON CONFLICT(node_id) DO NOTHING""",
            (
                node_id,
                str(member["hostname"]),
                str(member["role"]),
                str(member["main_user"]),
                main_uid,
                main_gid,
                generation,
            ),
        )


def apply_signed_config(payload: object, signature: str) -> int:
    bootstrap = load_pinned_fleet_bootstrap()
    config = normalize_config(payload)
    if config["fleet_id"] != bootstrap["fleet_id"]:
        raise BackupConfigStateError("Backup configuration belongs to a different fleet")
    if not verify_config(config, signature, bootstrap["fleet_signing_public_key"]):
        raise BackupConfigStateError("Backup configuration signature is invalid")
    identity = load_node_identity()
    if identity is None:
        raise BackupConfigStateError("Permanent local Node ID is unavailable")
    current = applied_config_generation()
    if config["generation"] < current:
        raise BackupConfigStateError("Backup configuration would roll back trusted state")
    if config["generation"] == current:
        return current

    relevant_job_target_ids = {
        item["target_uuid"] for item in config["jobs"]
        if item["source_node_id"] == identity.node_id
    }
    relevant_targets = [
        item for item in config["targets"]
        if item["host_node_id"] == identity.node_id
        or item["target_uuid"] in relevant_job_target_ids
    ]
    relevant_target_ids = {item["target_uuid"] for item in relevant_targets}
    relevant_jobs = [
        item for item in config["jobs"]
        if item["source_node_id"] == identity.node_id
        and item["target_uuid"] in relevant_target_ids
    ]

    conn = get_db_connection()
    try:
        _materialize_signed_fleet_references(conn, identity, config)
        conn.execute("UPDATE backup_targets SET enabled=0")
        conn.execute("UPDATE backup_jobs SET enabled=0 WHERE source_node_id=?", (identity.node_id,))
        target_db_ids: dict[str, int] = {}
        for item in relevant_targets:
            conn.execute(
                """INSERT INTO backup_targets(
                       target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,
                       repository_root,repository_relative_path,enabled)
                   VALUES(?,?,?,?,?,?,?,1)
                   ON CONFLICT(target_uuid) DO UPDATE SET
                     friendly_name=excluded.friendly_name,
                     host_node_id=excluded.host_node_id,
                     target_type=excluded.target_type,
                     filesystem_uuid=excluded.filesystem_uuid,
                     repository_root=excluded.repository_root,
                     repository_relative_path=excluded.repository_relative_path,
                     enabled=1""",
                (
                    item["target_uuid"], item["friendly_name"], item["host_node_id"],
                    (
                        "local_storage"
                        if item["host_node_id"] == identity.node_id
                        else "remote_storage"
                    ),
                    item["filesystem_uuid"], item["repository_root"],
                    item["repository_relative_path"],
                ),
            )
            row = conn.execute("SELECT id FROM backup_targets WHERE target_uuid=?", (item["target_uuid"],)).fetchone()
            target_db_ids[item["target_uuid"]] = int(row["id"])
        for item in relevant_jobs:
            source = conn.execute(
                "SELECT main_user,membership_state FROM fleet_nodes WHERE node_id=?",
                (item["source_node_id"],),
            ).fetchone()
            if source is None or source["membership_state"] != "active":
                raise BackupConfigStateError("Backup source is not an active fleet member")
            expected_home = f"/home/{source['main_user']}"
            if item["source_path"] != expected_home:
                raise BackupConfigStateError("Signed backup source does not match the node Home folder")
            conn.execute(
                """INSERT INTO backup_jobs(
                       job_uuid,source_node_id,target_id,source_path,enabled,paused,pause_reason)
                   VALUES(?,?,?,?,1,?,?)
                   ON CONFLICT(job_uuid) DO UPDATE SET
                     source_node_id=excluded.source_node_id,
                     target_id=excluded.target_id,
                     source_path=excluded.source_path,
                     enabled=1,
                     paused=excluded.paused,
                     pause_reason=excluded.pause_reason,
                     updated_at=CURRENT_TIMESTAMP""",
                (
                    item["job_uuid"], item["source_node_id"], target_db_ids[item["target_uuid"]],
                    item["source_path"], 1 if item["paused"] else 0, item["pause_reason"],
                ),
            )
        policy = config["policy"]
        conn.execute(
            """INSERT INTO backup_runtime_policy(
                   id,generation,schedule_hour,retention_daily,retention_weekly,
                   retention_monthly,free_space_reserve_percent,
                   deep_verification_days,persistent_alert_seconds,bandwidth_limit_kib)
               VALUES(1,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 generation=excluded.generation,
                 schedule_hour=excluded.schedule_hour,
                 retention_daily=excluded.retention_daily,
                 retention_weekly=excluded.retention_weekly,
                 retention_monthly=excluded.retention_monthly,
                 free_space_reserve_percent=excluded.free_space_reserve_percent,
                 deep_verification_days=excluded.deep_verification_days,
                 persistent_alert_seconds=excluded.persistent_alert_seconds,
                 bandwidth_limit_kib=excluded.bandwidth_limit_kib,
                 updated_at=CURRENT_TIMESTAMP""",
            (
                config["generation"], policy["schedule_hour"],
                policy["retention_daily"], policy["retention_weekly"],
                policy["retention_monthly"], policy["free_space_reserve_percent"],
                policy["deep_verification_days"], policy["persistent_alert_seconds"],
                policy["bandwidth_limit_kib"],
            ),
        )

        conn.execute(
            """INSERT INTO backup_config_applied_state(id,generation) VALUES(1,?)
               ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,updated_at=CURRENT_TIMESTAMP""",
            (config["generation"],),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return config["generation"]
