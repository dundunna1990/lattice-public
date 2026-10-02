"""Execute validated local backup jobs and record durable outcomes."""
from __future__ import annotations

from pathlib import Path
import logging
import os

from lattice.backup.credentials import (
    BackupCredentialError, create_password_file, validate_password_file,
)
from lattice.backup.restic import ResticError, ResticRepository, ResticSFTPRepository
from lattice.backup.remote import RemoteBackupError, connection_candidates, sftp_capacity
from lattice.backup.maintenance import BackupMaintenanceError, ensure_local_free_space
from lattice.backup.locks import BackupLockError, repository_operation_lock
from lattice.backup.config_state import runtime_policy
from lattice.backup.runs import begin_run, finish_run
from lattice.backup.source_policy import default_excludes, BackupSourcePolicyError
from lattice.backup.preflight import (
    BackupPreflightError, run_preflight, record_successful_preflight,
)
from lattice.backup.targets import LocalBackupTarget, resolve_repository_root
from lattice.file_access.identity import load_node_identity
from lattice.core.db import get_db_connection


class BackupExecutionError(RuntimeError):
    pass

logger = logging.getLogger(__name__)
DEFAULT_CREDENTIAL_ROOT = Path("/etc/lattice/backup/credentials")


def _password_file_for_backup(
    job: dict,
    credential_root: Path,
    *,
    repository_exists: bool | None = None,
) -> Path:
    path = Path(credential_root) / f"{job['job_uuid']}.password"
    if path.exists() or path.is_symlink():
        try:
            return validate_password_file(path)
        except BackupCredentialError as exc:
            raise BackupExecutionError(str(exc)) from exc

    conn = get_db_connection()
    try:
        previous_success = conn.execute(
            "SELECT 1 FROM backup_runs WHERE job_id=? AND result='successful' LIMIT 1",
            (int(job["id"]),),
        ).fetchone() is not None
    finally:
        conn.close()
    if previous_success or repository_exists is True:
        raise BackupExecutionError(
            "Backup credential is missing for an established encrypted repository"
        )
    try:
        return create_password_file(path)
    except BackupCredentialError as exc:
        raise BackupExecutionError(str(exc)) from exc


def _job_has_success(job_id: int) -> bool:
    conn = get_db_connection()
    try:
        return conn.execute(
            "SELECT 1 FROM backup_runs WHERE job_id=? AND result='successful' LIMIT 1",
            (int(job_id),),
        ).fetchone() is not None
    finally:
        conn.close()


def _load_job(job_id: int) -> dict:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.id, bj.job_uuid, bj.source_path, bj.source_node_id,
                      fn.hostname AS source_hostname, bt.target_uuid, bt.friendly_name,
                      bt.filesystem_uuid, bt.repository_root, bt.repository_relative_path, bt.host_node_id, bt.target_type
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.id=? AND bj.enabled=1 AND bt.enabled=1""",
            (job_id,),
        ).fetchone()
        if row is None:
            raise BackupExecutionError("Backup job was not found or its target is disabled")
        return dict(row)
    finally:
        conn.close()


def _load_local_job(job_id: int) -> dict:
    data = _load_job(job_id)
    if data["source_node_id"] != data["host_node_id"]:
        raise BackupExecutionError("Backup target is hosted by a different computer")
    return data


def _load_remote_job(job_id: int) -> dict:
    data = _load_job(job_id)
    if data["source_node_id"] == data["host_node_id"]:
        raise BackupExecutionError("Backup target is attached to this source computer")
    return data


def run_local_job(
    job_id: int,
    *,
    credential_root: Path = DEFAULT_CREDENTIAL_ROOT,
    repository_factory=ResticRepository,
    target_factory=LocalBackupTarget,
    target_resolver=resolve_repository_root,
    free_space_preflight=ensure_local_free_space,
    local_node_id: str | None = None,
    allow_large_first_backup: bool = False,
    preflight_runner=None,
    preflight_recorder=None,
) -> dict:
    job = _load_local_job(job_id)
    if local_node_id is None:
        identity = load_node_identity()
        if identity is None:
            raise BackupExecutionError("Local Lattice node identity is unavailable")
        local_node_id = identity.node_id
    if job["source_node_id"] != local_node_id:
        raise BackupExecutionError("Backup job belongs to a different source computer")
    try:
        with repository_operation_lock(job["job_uuid"], "backup"):
            if target_factory is LocalBackupTarget:
                repository_root, _mount = target_resolver(
                    job["filesystem_uuid"], job["repository_relative_path"]
                )
            else:
                # Test/custom factories may model the target independently.
                repository_root = Path(job["repository_root"])
                mount_path = repository_root.parent if repository_root.parent != Path('/') else repository_root
                target = target_factory(
                    target_id=job["target_uuid"], friendly_name=job["friendly_name"],
                    filesystem_uuid=job["filesystem_uuid"], mount_path=mount_path, repository_root=repository_root,
                )
                target.validate()
            repository_path = repository_root / job["source_node_id"]
            password_file = _password_file_for_backup(
                job,
                Path(credential_root),
                repository_exists=repository_path.exists(),
            )
            run = begin_run(job_id, recover_abandoned=True)
            established = _job_has_success(job["id"])
            try:
                if target_factory is LocalBackupTarget:
                    free_space_preflight(
                        job_id,
                        credential_root=credential_root,
                        repository_factory=repository_factory,
                        target_resolver=target_resolver,
                    )
                repo = repository_factory(repository_path, password_file)
                if not repository_path.exists():
                    repo.initialize()
                repo.clear_stale_locks()
                source = Path(job["source_path"])
                excludes = default_excludes(source, repository_path=repository_path)
                if preflight_runner is None:
                    preflight_runner = run_preflight
                filesystem = os.statvfs(repository_root)
                preflight = preflight_runner(
                    job_id,
                    source,
                    excludes,
                    established=established,
                    allow_large_first_backup=allow_large_first_backup,
                    target_total_bytes=filesystem.f_blocks * filesystem.f_frsize,
                    target_free_bytes=filesystem.f_bavail * filesystem.f_frsize,
                )
                for warning in getattr(preflight, "warnings", ()):
                    logger.warning("Backup preflight warning: %s", warning)
                repo.backup(source, excludes=excludes, hostname=job["source_hostname"])
                snapshots = repo.snapshots()
                matching = [s for s in snapshots if job["source_path"] in s.paths]
                if not matching:
                    raise BackupExecutionError("Backup completed but the expected snapshot could not be verified")
                snapshot = matching[-1]
                repo.check()
                try:
                    (preflight_recorder or record_successful_preflight)(job_id, preflight)
                except Exception:
                    logger.exception("Could not persist successful Backup preflight baseline")
                return finish_run(run["id"], result="successful", snapshot_id=snapshot.snapshot_id)
            except (
                ResticError,
                BackupExecutionError,
                BackupSourcePolicyError,
                BackupMaintenanceError,
                BackupPreflightError,
                OSError,
            ) as exc:
                try:
                    finish_run(run["id"], result="failed", error_message=str(exc)[:1000])
                finally:
                    raise BackupExecutionError(str(exc)) from exc
    except BackupLockError as exc:
        raise BackupExecutionError(str(exc)) from exc


def run_remote_job(
    job_id: int,
    *,
    credential_root: Path = DEFAULT_CREDENTIAL_ROOT,
    repository_factory=ResticSFTPRepository,
    connection_factory=connection_candidates,
    local_node_id: str | None = None,
    full_speed: bool = False,
    allow_large_first_backup: bool = False,
    preflight_runner=None,
    preflight_recorder=None,
    capacity_resolver=None,
) -> dict:
    job = _load_remote_job(job_id)
    if local_node_id is None:
        identity = load_node_identity()
        if identity is None:
            raise BackupExecutionError("Local Lattice node identity is unavailable")
        local_node_id = identity.node_id
    if job["source_node_id"] != local_node_id:
        raise BackupExecutionError("Backup job belongs to a different source computer")
    if not isinstance(full_speed, bool):
        raise BackupExecutionError("Full Speed override must be boolean")
    configured_limit = int(runtime_policy().get("bandwidth_limit_kib", 0))
    upload_limit_kib = None if full_speed or configured_limit <= 0 else configured_limit

    try:
        with repository_operation_lock(job["job_uuid"], "backup"):
            credential_path = Path(credential_root) / f"{job['job_uuid']}.password"
            established = _job_has_success(job["id"])
            if established and not (credential_path.exists() or credential_path.is_symlink()):
                raise BackupExecutionError(
                    "Backup credential is missing for an established encrypted repository"
                )
            try:
                connections = connection_factory(job)
            except RemoteBackupError as exc:
                raise BackupExecutionError(str(exc)) from exc
            if not connections:
                raise BackupExecutionError("No usable remote backup route is available")

            credential_preexisting = credential_path.exists() or credential_path.is_symlink()
            password_file = _password_file_for_backup(
                job,
                Path(credential_root),
                repository_exists=None,
            )
            credential_created = not credential_preexisting
            credential_committed = False

            run = begin_run(job_id, recover_abandoned=True)
            source = Path(job["source_path"])
            try:
                excludes = default_excludes(source)
            except BackupSourcePolicyError as exc:
                finish_run(run["id"], result="failed", error_message=str(exc)[:1000])
                raise BackupExecutionError(str(exc)) from exc

            last_error: Exception | None = None
            repo = None
            state = None
            selected_connection = None
            for connection in connections:
                candidate = repository_factory(
                    connection.repository,
                    password_file,
                    ssh_args=connection.ssh_args,
                    upload_limit_kib=upload_limit_kib,
                )
                try:
                    candidate_state = candidate.repository_state()
                except (ResticError, OSError) as exc:
                    last_error = exc
                    continue
                repo = candidate
                state = candidate_state
                selected_connection = connection
                break

            if repo is None or state is None or selected_connection is None:
                detail = str(last_error or "Remote backup failed")
                try:
                    finish_run(run["id"], result="failed", error_message=detail[:1000])
                finally:
                    if credential_created and not credential_committed:
                        password_file.unlink(missing_ok=True)
                    raise BackupExecutionError(detail) from last_error

            try:
                if state == "initialized":
                    credential_committed = True
                    repo.clear_stale_locks()
                elif state == "absent":
                    # Never silently recreate a repository that has
                    # previously held a successful backup. An absent repo
                    # after success means target state was lost or changed
                    # and requires operator attention.
                    if established:
                        raise BackupExecutionError(
                            "Established remote backup repository is missing; refusing to initialize a replacement"
                        )
                    repo.initialize()
                    credential_committed = True

                if capacity_resolver is None:
                    capacity_resolver = sftp_capacity
                try:
                    target_total_bytes, target_free_bytes = capacity_resolver(
                        selected_connection
                    )
                except RemoteBackupError as exc:
                    raise BackupExecutionError(
                        f"Could not verify remote backup capacity: {exc}"
                    ) from exc

                if preflight_runner is None:
                    preflight_runner = run_preflight
                preflight = preflight_runner(
                    job_id,
                    source,
                    excludes,
                    established=established,
                    allow_large_first_backup=allow_large_first_backup,
                    target_total_bytes=target_total_bytes,
                    target_free_bytes=target_free_bytes,
                )
                for warning in getattr(preflight, "warnings", ()):
                    logger.warning("Backup preflight warning: %s", warning)

                # Once one route has successfully opened the repository, pin
                # the entire data/verification operation to that route.
                # Post-backup failures must not fall through to unrelated or
                # stale route candidates and hide the real error.
                repo.backup(source, excludes=excludes, hostname=job["source_hostname"])
                snapshots = repo.snapshots()
                matching = [item for item in snapshots if job["source_path"] in item.paths]
                if not matching:
                    raise BackupExecutionError(
                        "Remote backup completed but the expected snapshot could not be verified"
                    )
                snapshot = matching[-1]
                repo.check()
                try:
                    (preflight_recorder or record_successful_preflight)(job_id, preflight)
                except Exception:
                    logger.exception("Could not persist successful Backup preflight baseline")
                return finish_run(
                    run["id"],
                    result="successful",
                    snapshot_id=snapshot.snapshot_id,
                )
            except (ResticError, BackupExecutionError, BackupPreflightError, OSError) as exc:
                detail = str(exc)
                try:
                    finish_run(run["id"], result="failed", error_message=detail[:1000])
                finally:
                    if credential_created and not credential_committed:
                        password_file.unlink(missing_ok=True)
                    raise BackupExecutionError(detail) from exc
    except BackupLockError as exc:
        raise BackupExecutionError(str(exc)) from exc
