"""Independent encrypted disaster-recovery kit for source-owned Lattice backups."""
from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from lattice.backup.credentials import BackupCredentialError, validate_password_file
from lattice.backup.keys import DEFAULT_BACKUP_SSH_DIR
from lattice.backup.transport import DEFAULT_BACKUP_PORT, backup_account_name, backup_host_alias
from lattice.backup.sync import BackupSyncError, get_cached_signed_backup_assignment
from lattice.core.db import get_db_connection
from lattice.core.lan_routes import is_local_only_virtual_interface
from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import FileKeyError, validate_ed25519_public_key

DEFAULT_CREDENTIAL_ROOT = Path("/etc/lattice/backup/credentials")
KIT_SCHEMA_VERSION = 1
OPENSSL_ITERATIONS = 300_000


class BackupRecoveryKitError(RuntimeError):
    pass


def _safe_root_secret(path: Path, *, maximum: int = 65536) -> str:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupRecoveryKitError(f"Required recovery material is unavailable: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size < 1
            or metadata.st_size > maximum
        ):
            raise BackupRecoveryKitError(f"Required recovery material is unsafe: {path}")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupRecoveryKitError(f"Required recovery material is not text: {path}") from exc


def _local_jobs(node_id: str) -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bj.job_uuid,bj.source_node_id,bj.source_path,
                      bt.target_uuid,bt.host_node_id,bt.filesystem_uuid,
                      bt.repository_relative_path,bt.repository_root,
                      fn.hostname AS target_hostname,fn.backup_host_public_key
               FROM backup_jobs bj
               JOIN backup_targets bt ON bt.id=bj.target_id
               JOIN fleet_nodes fn ON fn.node_id=bt.host_node_id
               WHERE bj.source_node_id=? AND bj.enabled=1 AND bt.enabled=1
               ORDER BY bj.id""",
            (node_id,),
        ).fetchall()
        result = [dict(row) for row in rows]
        for job in result:
            route_rows = conn.execute(
                """SELECT ip, interface_name, route_kind FROM peer_routes
                   WHERE node_id=?
                     AND last_seen_at >= datetime('now', '-30 days')
                   ORDER BY CASE WHEN last_success_at IS NULL THEN 1 ELSE 0 END,
                            last_success_at DESC, priority ASC, ip ASC LIMIT 16""",
                (job["host_node_id"],),
            ).fetchall()
            job["known_routes"] = [
                str(row[0])
                for row in route_rows
                if (
                    str(row[2] or "unknown") != "unknown"
                    and not is_local_only_virtual_interface(row[1])
                )
            ]
        return result
    finally:
        conn.close()


def _signed_remote_host_key(job: dict) -> str | None:
    try:
        cached = get_cached_signed_backup_assignment()
    except BackupSyncError as exc:
        raise BackupRecoveryKitError(f"Cached Backup assignment cannot be trusted: {exc}") from exc
    if cached is None:
        return None
    assignment, _signature = cached
    matches = [
        item for item in assignment["assignments"]
        if item["source_node_id"] == job["source_node_id"]
        and item["target_node_id"] == job["host_node_id"]
        and item["target_uuid"] == job["target_uuid"]
        and item["repository_id"] == job["job_uuid"]
    ]
    if len(matches) != 1:
        raise BackupRecoveryKitError(
            "Cached signed Backup assignment does not authorize this recovery job"
        )
    return str(matches[0]["backup_host_public_key"])


def build_recovery_payload() -> dict:
    if os.geteuid() != 0:
        raise BackupRecoveryKitError("Recovery kit export must run as root")
    identity = load_node_identity()
    if identity is None:
        raise BackupRecoveryKitError("Local Lattice node identity is unavailable")
    jobs = _local_jobs(identity.node_id)
    if not jobs:
        raise BackupRecoveryKitError("This computer has no enabled Backup jobs to export")

    client_private = _safe_root_secret(DEFAULT_BACKUP_SSH_DIR / "client_ed25519")
    try:
        client_public = validate_ed25519_public_key(
            (DEFAULT_BACKUP_SSH_DIR / "client_ed25519.pub").read_text(encoding="utf-8").strip()
        )
    except (OSError, ValueError) as exc:
        raise BackupRecoveryKitError("Backup client public key is unavailable or invalid") from exc

    exported_jobs: list[dict] = []
    for job in jobs:
        password_path = DEFAULT_CREDENTIAL_ROOT / f"{job['job_uuid']}.password"
        try:
            validate_password_file(password_path)
        except BackupCredentialError as exc:
            raise BackupRecoveryKitError(str(exc)) from exc
        password = _safe_root_secret(password_path, maximum=4096).rstrip("\n")
        remote = job["host_node_id"] != identity.node_id
        host_public_key = job.get("backup_host_public_key")
        if remote:
            signed_host_key = _signed_remote_host_key(job)
            if signed_host_key is not None:
                host_public_key = signed_host_key
            try:
                host_public_key = validate_ed25519_public_key(str(host_public_key or ""))
            except FileKeyError as exc:
                raise BackupRecoveryKitError(
                    f"Backup target {job['target_hostname']} has no trusted Backup host key"
                ) from exc
        exported_jobs.append({
            "job_uuid": job["job_uuid"],
            "source_node_id": job["source_node_id"],
            "source_path": job["source_path"],
            "restic_password": password,
            "target_uuid": job["target_uuid"],
            "target_node_id": job["host_node_id"],
            "target_hostname": job["target_hostname"],
            "filesystem_uuid": job["filesystem_uuid"],
            "repository_relative_path": job["repository_relative_path"],
            "physical_repository": str(
                Path(job["repository_root"]) / identity.node_id
            ),
            "remote": remote,
            "sftp_username": (
                backup_account_name(identity.node_id, job["target_uuid"])
                if remote else None
            ),
            "sftp_port": DEFAULT_BACKUP_PORT if remote else None,
            "sftp_repository_path": "repo" if remote else None,
            "target_host_alias": (
                backup_host_alias(job["host_node_id"]) if remote else None
            ),
            "target_host_public_key": host_public_key if remote else None,
            "known_routes": list(job.get("known_routes") or []),
        })
    return {
        "schema_version": KIT_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "node_id": identity.node_id,
            "hostname": getattr(identity, "hostname", None),
            "main_user": getattr(identity, "main_user", None),
        },
        "backup_client_private_key": client_private,
        "backup_client_public_key": client_public,
        "jobs": exported_jobs,
        "custody_warning": (
            "Store this encrypted kit separately from both the source computer "
            "and its sole backup target."
        ),
    }


def _openssl_crypt(data: bytes, passphrase: str, *, decrypt: bool) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise BackupRecoveryKitError("Recovery kit passphrase must be at least 12 characters")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, passphrase.encode("utf-8") + b"\n")
    finally:
        os.close(write_fd)
    command = [
        "/usr/bin/openssl", "enc",
        "-d" if decrypt else "-e",
        "-aes-256-cbc", "-pbkdf2", "-iter", str(OPENSSL_ITERATIONS),
        "-pass", f"fd:{read_fd}",
    ]
    if not decrypt:
        command.append("-salt")
    try:
        result = subprocess.run(
            command,
            input=data,
            capture_output=True,
            timeout=60,
            pass_fds=(read_fd,),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupRecoveryKitError(
            f"Could not run OpenSSL recovery-kit encryption: {exc}"
        ) from exc
    finally:
        os.close(read_fd)
    if result.returncode != 0:
        detail = (result.stderr or b"OpenSSL failed").decode("utf-8", "replace").strip()
        raise BackupRecoveryKitError(f"Recovery kit encryption/decryption failed: {detail[:500]}")
    return bytes(result.stdout)


def export_recovery_kit(output: Path, passphrase: str) -> Path:
    output = Path(output)
    if not output.is_absolute():
        raise BackupRecoveryKitError("Recovery kit output path must be absolute")
    if output.exists() or output.is_symlink():
        raise BackupRecoveryKitError("Recovery kit output already exists; refusing overwrite")
    payload = build_recovery_payload()
    plaintext = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    encrypted = _openssl_crypt(plaintext, passphrase, decrypt=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(descriptor, encrypted)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(output, 0o600)
    return output


def decrypt_recovery_kit(path: Path, passphrase: str) -> dict:
    path = Path(path)
    try:
        encrypted = path.read_bytes()
    except OSError as exc:
        raise BackupRecoveryKitError(f"Could not read recovery kit: {exc}") from exc
    plaintext = _openssl_crypt(encrypted, passphrase, decrypt=True)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupRecoveryKitError("Recovery kit plaintext is invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != KIT_SCHEMA_VERSION:
        raise BackupRecoveryKitError("Recovery kit schema is unsupported")
    if not isinstance(payload.get("jobs"), list) or not payload["jobs"]:
        raise BackupRecoveryKitError("Recovery kit contains no Backup jobs")
    return payload


def extract_recovery_kit(path: Path, destination: Path, passphrase: str) -> Path:
    payload = decrypt_recovery_kit(path, passphrase)
    destination = Path(destination)
    if not destination.is_absolute():
        raise BackupRecoveryKitError("Recovery workspace path must be absolute")
    if destination.exists() or destination.is_symlink():
        raise BackupRecoveryKitError("Recovery workspace already exists; refusing overwrite")
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)
    client_key = destination / "client_ed25519"
    client_key.write_text(payload["backup_client_private_key"], encoding="utf-8")
    os.chmod(client_key, 0o600)
    manifest = {k: v for k, v in payload.items() if k not in {"backup_client_private_key"}}
    # Keep job passwords out of the human-readable manifest; write one protected file per job.
    manifest_jobs = []
    for raw_job in payload["jobs"]:
        job = dict(raw_job)
        password = str(job.pop("restic_password"))
        password_file = destination / f"restic-{job['job_uuid']}.password"
        password_file.write_text(password + "\n", encoding="utf-8")
        os.chmod(password_file, 0o600)
        if job.get("remote") and job.get("target_host_public_key"):
            known_hosts = destination / f"known-hosts-{job['job_uuid']}"
            known_hosts.write_text(
                (
                    f"{job['target_host_alias']} "
                    f"{' '.join(str(job['target_host_public_key']).split()[:2])}\n"
                ),
                encoding="utf-8",
            )
            os.chmod(known_hosts, 0o600)
            job["known_hosts_file"] = known_hosts.name
        job["password_file"] = password_file.name
        manifest_jobs.append(job)
    manifest["jobs"] = manifest_jobs
    manifest_path = destination / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o600)
    instructions = destination / "RECOVERY.txt"
    instructions.write_text(
        "Lattice Backup offline recovery workspace\n\n"
        "This workspace contains sensitive keys and Restic passwords. Keep mode 0700/0600.\n"
        "Use manifest.json to identify the surviving repository. For a local/external "
        "target, mount\n"
        "the filesystem whose UUID matches filesystem_uuid and use the physical_repository path.\n"
        "For a remote target, use sftp_username, sftp_port, a known route/hostname, "
        "client_ed25519,\n"
        "and the job's known_hosts_file with strict host-key checking. Then run Restic with the\n"
        "job's password_file. Restore first into a separate staging directory; do not overwrite\n"
        "an existing Home until the restored data has been inspected.\n",
        encoding="utf-8",
    )
    os.chmod(instructions, 0o600)
    return destination
