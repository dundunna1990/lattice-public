"""Root-side application of one signed Lattice backup transport assignment."""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile

from lattice.backup.assignment import BackupAssignmentError, normalize_assignment
from lattice.backup.keys import DEFAULT_BACKUP_SSH_DIR, ensure_backup_host_identity
from lattice.backup.transport import (
    DEFAULT_AUTHORIZED_KEYS_DIR,
    DEFAULT_CHROOT_ROOT,
    DEFAULT_HOST_KEY,
    BackupTransportAccount,
    render_authorized_key,
    render_sshd_config,
)
from lattice.backup.transport_plan import BackupTransportPlanError, build_local_transport_plan
from lattice.file_access.home_export import FileHomeExportError, exact_mount_source
from lattice.file_access.identity import load_node_identity
from lattice.file_access.applied_state import BACKUP_APPLIED_PATH, write_applied_state
from lattice.file_access.keys import validate_ed25519_public_key

REQUEST_PATH = Path("/var/lib/lattice/backup-transport-request.json")
DESIRED_STATE_PATH = Path("/var/lib/lattice/backup-transport-desired.json")
SSHD_CONFIG = DEFAULT_BACKUP_SSH_DIR / "sshd_config"
WORKER_BOOTSTRAP = Path("/etc/lattice/fleet/bootstrap.json")
MASTER_SIGNING_PUBLIC = Path("/etc/lattice/fleet-signing/fleet_signing_ed25519.pub")


class BackupTransportApplyError(RuntimeError):
    pass


def _safe_read(path: Path, *, allowed_uids: set[int], maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupTransportApplyError(f"{path} is not a single regular file")
        if metadata.st_uid not in allowed_uids:
            raise BackupTransportApplyError(f"{path} has unexpected ownership")
        if metadata.st_mode & 0o022:
            raise BackupTransportApplyError(f"{path} is writable by group or others")
        if metadata.st_size > maximum:
            raise BackupTransportApplyError(f"{path} is unexpectedly large")
        return os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)


def _safe_json(path: Path, *, allowed_uids: set[int], maximum: int) -> dict:
    try:
        payload = json.loads(
            _safe_read(path, allowed_uids=allowed_uids, maximum=maximum).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupTransportApplyError(f"Could not safely read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BackupTransportApplyError(f"{path} does not contain a JSON object")
    return payload


def _safe_public_key(path: Path) -> str:
    try:
        return validate_ed25519_public_key(
            _safe_read(path, allowed_uids={0}, maximum=4096).decode("utf-8").strip()
        )
    except Exception as exc:
        if isinstance(exc, BackupTransportApplyError):
            raise
        raise BackupTransportApplyError(f"Could not safely read {path}: {exc}") from exc


def _trusted_signing_key() -> str:
    if WORKER_BOOTSTRAP.exists():
        payload = _safe_json(WORKER_BOOTSTRAP, allowed_uids={0}, maximum=32768)
        try:
            return validate_ed25519_public_key(payload["fleet_signing_public_key"])
        except Exception as exc:
            raise BackupTransportApplyError("Worker fleet signing key is invalid") from exc
    if MASTER_SIGNING_PUBLIC.exists():
        return _safe_public_key(MASTER_SIGNING_PUBLIC)
    raise BackupTransportApplyError("No pinned fleet signing public key exists")


def _atomic_write(path: Path, content: str, *, mode: int, uid: int = 0, gid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BackupTransportApplyError(f"Refusing to replace unsafe path {path}")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupTransportApplyError(f"Could not execute {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise BackupTransportApplyError(f"{command[0]} failed: {detail}")
    return result


def _ensure_account(username: str, *, runner=_run):
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        runner([
            "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
            "--home-dir", "/", "--shell", "/usr/sbin/nologin", username,
        ])
        try:
            account = pwd.getpwnam(username)
        except KeyError as exc:
            raise BackupTransportApplyError(
                f"Backup transport account {username} was not created"
            ) from exc
    if account.pw_uid == 0 or account.pw_dir != "/" or account.pw_shell not in {
        "/usr/sbin/nologin", "/bin/false",
    }:
        raise BackupTransportApplyError(
            f"Existing account {username} is unsafe for backup transport"
        )
    return account


def _ensure_directory(path: Path, *, mode: int, uid: int, gid: int) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BackupTransportApplyError(f"Expected safe directory at {path}")
    else:
        path.mkdir(parents=True, exist_ok=False)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _same_directory(source: Path, target: Path) -> bool:
    try:
        source_stat = source.stat()
        target_stat = target.stat()
    except OSError:
        return False
    return source_stat.st_dev == target_stat.st_dev and source_stat.st_ino == target_stat.st_ino


def _ensure_bind(source: Path, target: Path, *, runner=_run) -> None:
    try:
        mounted = exact_mount_source(target)
    except FileHomeExportError as exc:
        raise BackupTransportApplyError(str(exc)) from exc
    if mounted is not None:
        if not _same_directory(source, target):
            raise BackupTransportApplyError(
                f"Backup chroot target {target} is occupied by an unexpected mount"
            )
        return
    runner(["/usr/bin/mount", "--bind", str(source), str(target)])
    if not _same_directory(source, target):
        raise BackupTransportApplyError(f"Backup repository bind did not converge at {target}")


def apply_request(request_path: Path = REQUEST_PATH, *, runner=_run) -> int:
    if os.geteuid() != 0:
        raise BackupTransportApplyError("Backup transport reconciliation must run as root")
    if request_path != REQUEST_PATH:
        raise BackupTransportApplyError("Only the fixed Lattice backup request path is accepted")
    try:
        lattice = pwd.getpwnam("lattice")
    except KeyError as exc:
        raise BackupTransportApplyError("The lattice service account is unavailable") from exc
    request = _safe_json(
        request_path, allowed_uids={0, lattice.pw_uid}, maximum=524288
    )
    try:
        assignment = request["assignment"]
        signature = str(request["signature"])
    except KeyError as exc:
        raise BackupTransportApplyError("Backup transport request is incomplete") from exc
    identity = load_node_identity()
    if identity is None:
        raise BackupTransportApplyError("Permanent local Node ID is missing")
    host_pair = ensure_backup_host_identity(DEFAULT_BACKUP_SSH_DIR)
    try:
        plan = build_local_transport_plan(
            assignment,
            signature,
            _trusted_signing_key(),
            local_node_id=identity.node_id,
            local_host_public_key=host_pair.public_key_text,
        )
    except (BackupAssignmentError, BackupTransportPlanError) as exc:
        raise BackupTransportApplyError(str(exc)) from exc

    _ensure_directory(DEFAULT_CHROOT_ROOT, mode=0o755, uid=0, gid=0)
    _ensure_directory(DEFAULT_AUTHORIZED_KEYS_DIR, mode=0o755, uid=0, gid=0)
    accounts: list[BackupTransportAccount] = []
    for item in plan:
        account = _ensure_account(item.username, runner=runner)
        chroot = DEFAULT_CHROOT_ROOT / item.username
        _ensure_directory(chroot, mode=0o755, uid=0, gid=0)
        source_repo = item.repository_path
        _ensure_directory(
            source_repo, mode=0o700, uid=account.pw_uid, gid=account.pw_gid
        )
        repo_target = chroot / "repo"
        if exact_mount_source(repo_target) is None:
            _ensure_directory(repo_target, mode=0o755, uid=0, gid=0)
        _ensure_bind(source_repo, repo_target, runner=runner)
        _atomic_write(
            DEFAULT_AUTHORIZED_KEYS_DIR / item.username,
            render_authorized_key(item.account.public_key),
            mode=0o644,
        )
        accounts.append(item.account)

    if accounts:
        _atomic_write(
            SSHD_CONFIG,
            render_sshd_config(
                accounts,
                host_key=DEFAULT_HOST_KEY,
                authorized_keys_dir=DEFAULT_AUTHORIZED_KEYS_DIR,
                chroot_root=DEFAULT_CHROOT_ROOT,
            ),
            mode=0o600,
        )
    else:
        # No local remote repositories means no backup SSH listener should exist.
        SSHD_CONFIG.unlink(missing_ok=True)
    _atomic_write(
        DESIRED_STATE_PATH,
        json.dumps(
            {"schema_version": 1, "accounts": sorted(account.username for account in accounts)},
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n",
        mode=0o600,
    )
    return len(accounts)


def finalize_request(request_path: Path = REQUEST_PATH) -> int:
    """Acknowledge one transport generation only after activation/cleanup succeeded."""
    if os.geteuid() != 0:
        raise BackupTransportApplyError("Backup transport reconciliation must run as root")
    if request_path != REQUEST_PATH:
        raise BackupTransportApplyError("Only the fixed Lattice backup request path is accepted")
    try:
        lattice = pwd.getpwnam("lattice")
    except KeyError as exc:
        raise BackupTransportApplyError("The lattice service account is unavailable") from exc
    request = _safe_json(request_path, allowed_uids={0, lattice.pw_uid}, maximum=524288)
    try:
        assignment = normalize_assignment(request["assignment"])
        signature = str(request["signature"])
    except (KeyError, BackupAssignmentError) as exc:
        raise BackupTransportApplyError("Backup transport request is invalid") from exc
    identity = load_node_identity()
    if identity is None:
        raise BackupTransportApplyError("Permanent local Node ID is missing")
    host_pair = ensure_backup_host_identity(DEFAULT_BACKUP_SSH_DIR)
    try:
        build_local_transport_plan(
            assignment, signature, _trusted_signing_key(),
            local_node_id=identity.node_id,
            local_host_public_key=host_pair.public_key_text,
        )
    except (BackupAssignmentError, BackupTransportPlanError) as exc:
        raise BackupTransportApplyError(str(exc)) from exc
    generation = int(assignment["generation"])
    write_applied_state(BACKUP_APPLIED_PATH, node_id=identity.node_id, generation=generation)
    request_path.unlink(missing_ok=True)
    return generation


def main() -> None:
    import sys
    if sys.argv[1:] == ["--finalize"]:
        generation = finalize_request()
        print(f"Activated Lattice backup transport generation {generation}")
        return
    if sys.argv[1:]:
        raise SystemExit("usage: lattice.backup.transport_apply [--finalize]")
    count = apply_request()
    print(f"Prepared Lattice backup transport for {count} source(s)")


if __name__ == "__main__":
    main()
