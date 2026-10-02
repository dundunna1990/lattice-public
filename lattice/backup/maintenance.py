"""Retention, capacity safety, and deeper repository verification."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile

from lattice.backup.credentials import BackupCredentialError, validate_password_file
from lattice.backup.remote import RemoteBackupError, connection_candidates
from lattice.backup.locks import BackupLockError, repository_operation_lock
from lattice.backup.restic import ResticError, ResticRepository, ResticSFTPRepository
from lattice.backup.targets import resolve_repository_root
from lattice.backup.config_state import runtime_policy
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

DEFAULT_CREDENTIAL_ROOT = Path('/etc/lattice/backup/credentials')
DEFAULT_VERIFICATION_STAGING_ROOT = Path('/var/lib/lattice/backup/verification-staging')
MAX_RESTORE_PROBE_BYTES = 1024 * 1024
MAX_RESTORE_PROBE_DIRECTORIES = 64


class BackupMaintenanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapacityState:
    total_bytes: int
    free_bytes: int
    reserve_percent: int

    @property
    def free_percent(self) -> float:
        return 0.0 if self.total_bytes <= 0 else (self.free_bytes / self.total_bytes) * 100.0

    @property
    def reserve_satisfied(self) -> bool:
        return self.free_percent >= self.reserve_percent


def capacity_for_path(path: Path, *, reserve_percent: int) -> CapacityState:
    stats = os.statvfs(Path(path))
    total = int(stats.f_blocks * stats.f_frsize)
    free = int(stats.f_bavail * stats.f_frsize)
    if total <= 0 or free < 0 or free > total:
        raise BackupMaintenanceError('Backup target reported invalid capacity')
    return CapacityState(total, free, reserve_percent)


def _job(job_id: int) -> dict:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.id, bj.job_uuid, bj.source_node_id, bj.source_path,
                      fn.hostname AS source_hostname,
                      bt.target_uuid, bt.target_type, bt.host_node_id,
                      bt.filesystem_uuid, bt.repository_root, bt.repository_relative_path, bt.enabled
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.id=?""",
            (job_id,),
        ).fetchone()
        if row is None or not bool(row['enabled']):
            raise BackupMaintenanceError('Backup job or target is unavailable')
        return dict(row)
    finally:
        conn.close()


def _policy() -> tuple[int, int, int, int, int]:
    policy = runtime_policy()
    return (
        int(policy["retention_daily"]),
        int(policy["retention_weekly"]),
        int(policy["retention_monthly"]),
        int(policy["free_space_reserve_percent"]),
        int(policy["deep_verification_days"]),
    )


def apply_normal_retention(repo, job: dict) -> None:
    daily, weekly, monthly, _, _ = _policy()
    repo.apply_retention(
        keep_daily=daily,
        keep_weekly=weekly,
        keep_monthly=monthly,
        hostname=job['source_hostname'],
        prune=True,
    )
    snapshots = [
        item for item in repo.snapshots()
        if job['source_path'] in item.paths
    ]
    if not snapshots:
        raise BackupMaintenanceError(
            'Retention completed but no protected snapshot remains'
        )


def ensure_local_free_space(
    job_id: int,
    *,
    credential_root: Path = DEFAULT_CREDENTIAL_ROOT,
    repository_factory=ResticRepository,
    target_resolver=resolve_repository_root,
    capacity_reader=capacity_for_path,
) -> CapacityState:
    """Use normal retention first; never delete extra snapshots to chase reserve."""
    job = _job(job_id)
    if job['source_node_id'] != job['host_node_id']:
        raise BackupMaintenanceError('Free-space preflight is only local-storage aware')
    identity = load_node_identity()
    if identity is None or identity.node_id != job['source_node_id']:
        raise BackupMaintenanceError('Backup job belongs to a different source computer')
    repository_root, mount = target_resolver(
        job['filesystem_uuid'], job['repository_relative_path']
    )
    _, _, _, reserve, _ = _policy()
    state = capacity_reader(mount.target, reserve_percent=reserve)
    if state.reserve_satisfied:
        return state
    repository_path = repository_root / job['source_node_id']
    if not repository_path.exists():
        raise BackupMaintenanceError(
            f'Backup target has only {state.free_percent:.1f}% free; reserve is {reserve}%'
        )
    try:
        password_file = validate_password_file(
            Path(credential_root) / f"{job['job_uuid']}.password"
        )
    except BackupCredentialError as exc:
        raise BackupMaintenanceError(str(exc)) from exc
    repo = repository_factory(repository_path, password_file)
    apply_normal_retention(repo, job)
    state = capacity_reader(mount.target, reserve_percent=reserve)
    if not state.reserve_satisfied:
        raise BackupMaintenanceError(
            f'Backup target remains below the {reserve}% free-space reserve after normal retention'
        )
    return state


def deep_verification_due(job_id: int, *, now: datetime | None = None) -> bool:
    _, _, _, _, interval_days = _policy()
    now = now or datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT last_deep_verification_at FROM backup_maintenance_state WHERE job_id=?",
            (job_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row['last_deep_verification_at'] is None:
        return True
    try:
        previous = datetime.fromisoformat(row['last_deep_verification_at'])
    except ValueError:
        return True
    if previous.tzinfo is None:
        previous = previous.replace(tzinfo=timezone.utc)
    return now >= previous + timedelta(days=interval_days)


def _record_maintenance(job_id: int, *, retention: bool = False, deep: bool = False,
                        result: str = 'healthy', error: str | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT INTO backup_maintenance_state(
                   job_id,last_retention_at,last_deep_verification_at,last_result,last_error,updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(job_id) DO UPDATE SET
                 last_retention_at=CASE WHEN ? THEN excluded.last_retention_at ELSE backup_maintenance_state.last_retention_at END,
                 last_deep_verification_at=CASE WHEN ? THEN excluded.last_deep_verification_at ELSE backup_maintenance_state.last_deep_verification_at END,
                 last_result=excluded.last_result,
                 last_error=excluded.last_error,
                 updated_at=excluded.updated_at""",
            (
                job_id, now if retention else None, now if deep else None,
                result, error, now, int(retention), int(deep),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _latest_protected_snapshot(repo, job: dict):
    snapshots = [
        item for item in repo.snapshots()
        if job['source_path'] in item.paths
    ]
    if not snapshots:
        raise BackupMaintenanceError(
            'No protected snapshot is available for restore verification'
        )
    return max(snapshots, key=lambda item: item.time)


def _restore_probe_entry(repo, job: dict, snapshot_id: str):
    root = PurePosixPath(job['source_path'])
    pending = [str(root)]
    visited = 0
    while pending and visited < MAX_RESTORE_PROBE_DIRECTORIES:
        directory = pending.pop(0)
        visited += 1
        entries = repo.list_snapshot_directory(snapshot_id, directory, limit=500)
        for entry in entries:
            if (
                entry.entry_type == 'file'
                and 0 < entry.size <= MAX_RESTORE_PROBE_BYTES
            ):
                return entry
        for entry in entries:
            if entry.entry_type == 'dir':
                pending.append(entry.path)
    raise BackupMaintenanceError(
        'No small regular file was available for restore verification'
    )


def _verification_staging_root() -> Path:
    root = Path(os.environ.get(
        'LATTICE_BACKUP_VERIFICATION_STAGING_ROOT',
        str(DEFAULT_VERIFICATION_STAGING_ROOT),
    ))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return root


def verify_restore_probe(repo, job: dict) -> dict:
    snapshot = _latest_protected_snapshot(repo, job)
    entry = _restore_probe_entry(repo, job, snapshot.snapshot_id)
    root = _verification_staging_root()
    staging = Path(tempfile.mkdtemp(prefix='probe-', dir=root))
    os.chmod(staging, 0o700)
    try:
        repo.restore_to_staging(
            snapshot.snapshot_id,
            staging,
            include=entry.path,
        )
        selected = PurePosixPath(entry.path)
        restored = staging.joinpath(*selected.parts[1:])
        resolved = restored.resolve(strict=False)
        try:
            resolved.relative_to(staging.resolve(strict=False))
        except ValueError as exc:
            raise BackupMaintenanceError(
                'Restore verification escaped its staging directory'
            ) from exc
        if not restored.is_file() or restored.is_symlink():
            raise BackupMaintenanceError(
                'Restore verification did not produce the expected regular file'
            )
        restored_bytes = restored.read_bytes()
        if len(restored_bytes) > MAX_RESTORE_PROBE_BYTES:
            raise BackupMaintenanceError(
                'Restore verification file exceeded its safety bound'
            )
        expected_bytes = repo.dump_snapshot_file(snapshot.snapshot_id, entry.path)
        if len(expected_bytes) > MAX_RESTORE_PROBE_BYTES:
            raise BackupMaintenanceError(
                'Repository verification file exceeded its safety bound'
            )
        restored_hash = hashlib.sha256(restored_bytes).hexdigest()
        expected_hash = hashlib.sha256(expected_bytes).hexdigest()
        if (
            len(restored_bytes) != entry.size
            or len(expected_bytes) != entry.size
            or restored_hash != expected_hash
        ):
            raise BackupMaintenanceError(
                'Restored verification file did not match repository data'
            )
        return {
            'snapshot_id': snapshot.snapshot_id,
            'path': entry.path,
            'size': entry.size,
            'sha256': restored_hash,
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _verify(repo, job: dict, *, deep: bool) -> None:
    job_id = int(job['id'])
    kind = 'deep' if deep else 'quick'
    started = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO backup_verifications(job_id,kind,started_at,result) VALUES(?,?,?,'running')",
            (job_id, kind, started),
        )
        verification_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()
    try:
        repo.check(read_data_subset='5%' if deep else None)
        if deep:
            verify_restore_probe(repo, job)
    except Exception as exc:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE backup_verifications SET finished_at=?,result='failed',error_message=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), str(exc)[:1000], verification_id),
            )
            conn.commit()
        finally:
            conn.close()
        raise
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE backup_verifications SET finished_at=?,result='successful' WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), verification_id),
        )
        conn.commit()
    finally:
        conn.close()


def _maintain_job_unlocked(
    job_id: int,
    *,
    credential_root: Path = DEFAULT_CREDENTIAL_ROOT,
    local_repository_factory=ResticRepository,
    remote_repository_factory=ResticSFTPRepository,
    remote_connections=connection_candidates,
) -> None:
    job = _job(job_id)
    identity = load_node_identity()
    if identity is None or identity.node_id != job['source_node_id']:
        raise BackupMaintenanceError('Backup maintenance belongs to a different source computer')
    try:
        password_file = validate_password_file(
            Path(credential_root) / f"{job['job_uuid']}.password"
        )
    except BackupCredentialError as exc:
        raise BackupMaintenanceError(str(exc)) from exc
    deep = deep_verification_due(job_id)
    try:
        if job['host_node_id'] == identity.node_id:
            repository_root, _mount = resolve_repository_root(
                job['filesystem_uuid'], job['repository_relative_path']
            )
            repo = local_repository_factory(
                repository_root / job['source_node_id'], password_file
            )
            apply_normal_retention(repo, job)
            _verify(repo, job, deep=deep)
        elif job['host_node_id'] != identity.node_id:
            last_error = None
            for connection in remote_connections(job):
                try:
                    repo = remote_repository_factory(
                        connection.repository, password_file, ssh_args=connection.ssh_args
                    )
                    apply_normal_retention(repo, job)
                    _verify(repo, job, deep=deep)
                    last_error = None
                    break
                except (ResticError, BackupMaintenanceError, OSError) as exc:
                    last_error = exc
            if last_error is not None:
                raise last_error
        else:
            raise BackupMaintenanceError('Backup job target/source relationship is invalid')
    except (ResticError, RemoteBackupError, BackupMaintenanceError, OSError) as exc:
        _record_maintenance(job_id, result='failed', error=str(exc)[:1000])
        raise BackupMaintenanceError(str(exc)) from exc
    _record_maintenance(job_id, retention=True, deep=deep, result='healthy')


def maintain_job(
    job_id: int,
    *,
    credential_root: Path = DEFAULT_CREDENTIAL_ROOT,
    local_repository_factory=ResticRepository,
    remote_repository_factory=ResticSFTPRepository,
    remote_connections=connection_candidates,
) -> None:
    job = _job(job_id)
    try:
        with repository_operation_lock(job["job_uuid"], "maintenance"):
            return _maintain_job_unlocked(
                job_id,
                credential_root=credential_root,
                local_repository_factory=local_repository_factory,
                remote_repository_factory=remote_repository_factory,
                remote_connections=remote_connections,
            )
    except BackupLockError as exc:
        raise BackupMaintenanceError(str(exc)) from exc
