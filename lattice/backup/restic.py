"""Narrow, non-shell Restic adapter for Lattice-managed repositories."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import shutil
import shlex
import subprocess
from typing import Iterable, Sequence

from lattice.backup.credentials import validate_password_file
from lattice.backup.models import BackupEntry, BackupSnapshot, BackupSnapshotStats


class ResticError(RuntimeError):
    def __init__(self, message: str, *, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


DEFAULT_MANAGED_RESTIC = Path("/opt/lattice/bin/restic")
DEFAULT_RESTIC_CACHE_DIR = Path("/var/lib/lattice-root/restic-cache")


def _resolve_restic_binary(binary: str | None) -> str:
    if binary is not None:
        resolved = shutil.which(binary) if "/" not in binary else binary
        if not resolved:
            raise ResticError("Restic is not installed or is not available in PATH")
        return str(resolved)
    managed = Path(os.environ.get("LATTICE_RESTIC_BINARY", str(DEFAULT_MANAGED_RESTIC)))
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    resolved = shutil.which("restic")
    if not resolved:
        raise ResticError(
            "Restic is not installed: the Lattice-managed Restic binary is unavailable"
        )
    return str(resolved)


class ResticRepository:
    def __init__(self, repository: Path, password_file: Path, *, binary: str | None = None) -> None:
        self.repository = str(Path(repository))
        self.password_file = validate_password_file(password_file)
        if not Path(self.repository).is_absolute():
            raise ResticError("Restic repository path must be absolute")
        self.binary = _resolve_restic_binary(binary)
        self.backend_options: tuple[str, ...] = ()

    def _run(self, args: Sequence[str], *, timeout: int = 3600) -> subprocess.CompletedProcess[str]:
        cache_dir = Path(
            os.environ.get("LATTICE_RESTIC_CACHE_DIR", str(DEFAULT_RESTIC_CACHE_DIR))
        )
        command = [
            self.binary,
            "--repo", self.repository,
            "--password-file", str(self.password_file),
            "--cache-dir", str(cache_dir),
            *self.backend_options,
            *args,
        ]
        try:
            result = subprocess.run(
                command, check=False, capture_output=True, text=True, timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResticError("Restic execution failed") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "unknown Restic error").strip()
            raise ResticError(
                f"Restic command failed: {detail[:1000]}",
                returncode=result.returncode,
            )
        return result

    def repository_state(self) -> str:
        """Return initialized/absent without letting stale locks block probing."""
        try:
            self._run(["--no-lock", "cat", "config"], timeout=120)
        except ResticError as exc:
            if exc.returncode == 10:
                return "absent"
            raise
        return "initialized"

    def initialize(self) -> None:
        Path(self.repository).parent.mkdir(parents=True, exist_ok=True)
        self._run(["init"], timeout=120)

    def backup(
        self, source: Path, *, excludes: Iterable[Path | str] = (), hostname: str | None = None
    ) -> None:
        source = Path(source)
        if not source.is_absolute():
            raise ResticError("Backup source must be absolute")
        args = [
            "backup", str(source),
            "--one-file-system",
            "--exclude-caches",
            "--exclude-if-present", ".lattice-exclude-dir",
            "--exclude-if-present", "pyvenv.cfg",
        ]
        for value in excludes:
            args.extend(["--exclude", str(value)])
        if hostname:
            args.extend(["--host", hostname])
        self._run(args)

    def snapshots(self) -> list[BackupSnapshot]:
        result = self._run(["snapshots", "--json"], timeout=120)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ResticError("Restic returned invalid snapshot metadata") from exc
        if not isinstance(payload, list):
            raise ResticError("Restic snapshot metadata has an invalid shape")
        snapshots: list[BackupSnapshot] = []
        for item in payload:
            if not isinstance(item, dict):
                raise ResticError("Restic snapshot entry is invalid")
            snapshot_id = item.get("id") or item.get("short_id")
            time = item.get("time")
            hostname = item.get("hostname", "")
            paths = item.get("paths", [])
            if not isinstance(snapshot_id, str) or not isinstance(time, str) or not isinstance(paths, list):
                raise ResticError("Restic snapshot entry is incomplete")
            snapshots.append(BackupSnapshot(snapshot_id, time, str(hostname), tuple(str(p) for p in paths)))
        return snapshots

    def snapshot_restore_stats(self, snapshot_id: str) -> BackupSnapshotStats:
        if not isinstance(snapshot_id, str) or not snapshot_id or any(ch.isspace() for ch in snapshot_id):
            raise ResticError("Snapshot ID is invalid")
        result = self._run(
            ["stats", "--json", "--mode", "restore-size", snapshot_id],
            timeout=300,
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ResticError("Restic returned invalid snapshot size metadata") from exc
        if not isinstance(payload, dict):
            raise ResticError("Restic snapshot size metadata has an invalid shape")
        total_size = payload.get("total_size")
        total_file_count = payload.get("total_file_count")
        if (
            isinstance(total_size, bool)
            or not isinstance(total_size, int)
            or total_size < 0
            or isinstance(total_file_count, bool)
            or not isinstance(total_file_count, int)
            or total_file_count < 0
        ):
            raise ResticError("Restic snapshot size metadata is incomplete")
        return BackupSnapshotStats(
            total_size=total_size,
            total_file_count=total_file_count,
        )

    def list_snapshot_directory(
        self,
        snapshot_id: str,
        directory: str,
        *,
        limit: int = 500,
    ) -> list[BackupEntry]:
        if not isinstance(snapshot_id, str) or not snapshot_id or any(ch.isspace() for ch in snapshot_id):
            raise ResticError("Snapshot ID is invalid")
        if not isinstance(directory, str) or not directory.startswith("/") or "\x00" in directory:
            raise ResticError("Snapshot browse path must be absolute")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ResticError("Snapshot browse limit is invalid")
        requested = PurePosixPath(directory)
        if ".." in requested.parts:
            raise ResticError("Snapshot browse path is unsafe")
        result = self._run(["ls", "--json", snapshot_id, str(requested)], timeout=300)
        entries: list[BackupEntry] = []
        for raw_line in result.stdout.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ResticError("Restic returned invalid file-list metadata") from exc
            if not isinstance(item, dict):
                raise ResticError("Restic file-list entry is invalid")
            struct_type = item.get("struct_type") or item.get("message_type")
            if struct_type == "snapshot":
                continue
            if struct_type not in {"node", None}:
                # Forward-compatible: unknown metadata messages do not become files.
                continue
            path = item.get("path")
            name = item.get("name")
            entry_type = item.get("type")
            size = item.get("size", 0)
            mtime = item.get("mtime")
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or not isinstance(name, str)
                or not name
                or not isinstance(entry_type, str)
                or not entry_type
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
            ):
                raise ResticError("Restic file-list entry is incomplete")
            candidate = PurePosixPath(path)
            try:
                candidate.relative_to(requested)
            except ValueError as exc:
                raise ResticError("Restic file-list entry escaped the requested directory") from exc
            if candidate == requested:
                continue
            if candidate.parent != requested:
                # Directory-filtered ls should be shallow without --recursive.
                # Refuse unexpected deeper entries rather than presenting an
                # ambiguous tree to the operator.
                raise ResticError("Restic returned an unexpectedly recursive file listing")
            if mtime is not None and not isinstance(mtime, str):
                raise ResticError("Restic file modification time is invalid")
            entries.append(
                BackupEntry(
                    path=path,
                    name=name,
                    entry_type=entry_type,
                    size=size,
                    modified_at=mtime,
                )
            )
            if len(entries) >= limit:
                break
        return entries

    def dump_snapshot_file(self, snapshot_id: str, path: str) -> bytes:
        """Read one bounded snapshot file directly from the repository."""
        if (
            not isinstance(snapshot_id, str)
            or not snapshot_id
            or any(ch.isspace() for ch in snapshot_id)
        ):
            raise ResticError("Snapshot ID is invalid")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "\x00" in path
            or ".." in PurePosixPath(path).parts
        ):
            raise ResticError("Snapshot file path is invalid")
        command = [
            self.binary,
            "--repo", self.repository,
            "--password-file", str(self.password_file),
            "--cache-dir", str(Path(
                os.environ.get("LATTICE_RESTIC_CACHE_DIR", str(DEFAULT_RESTIC_CACHE_DIR))
            )),
            *self.backend_options,
            "dump", snapshot_id, path,
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=300,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResticError("Restic snapshot file read failed") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or b"unknown Restic error")
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", errors="replace")
            raise ResticError(
                f"Restic snapshot file read failed: {str(detail).strip()[:1000]}",
                returncode=result.returncode,
            )
        return bytes(result.stdout)

    def clear_stale_locks(self) -> None:
        """Remove only locks Restic itself considers stale."""
        self._run(["unlock"], timeout=120)

    def check(self, *, read_data_subset: str | None = None) -> None:
        args = ["check"]
        if read_data_subset:
            args.extend(["--read-data-subset", read_data_subset])
        self._run(args)

    def apply_retention(
        self,
        *,
        keep_daily: int,
        keep_weekly: int,
        keep_monthly: int,
        hostname: str | None = None,
        prune: bool = True,
    ) -> None:
        values = (keep_daily, keep_weekly, keep_monthly)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in values):
            raise ResticError("Restic retention values must be positive integers")
        args = [
            "forget",
            "--keep-daily", str(keep_daily),
            "--keep-weekly", str(keep_weekly),
            "--keep-monthly", str(keep_monthly),
        ]
        if hostname:
            args.extend(["--host", hostname])
        if prune:
            args.append("--prune")
        self._run(args, timeout=7200 if prune else 120)

    def restore_to_staging(
        self, snapshot_id: str, staging_dir: Path, *, include: str | None = None
    ) -> Path:
        if not snapshot_id or any(ch.isspace() for ch in snapshot_id):
            raise ResticError("Snapshot ID is invalid")
        staging = Path(staging_dir)
        if not staging.is_absolute():
            raise ResticError("Restore staging path must be absolute")
        staging.mkdir(parents=True, exist_ok=True)
        args = ["restore", snapshot_id, "--target", str(staging)]
        if include is not None:
            if not include.startswith("/") or "\x00" in include:
                raise ResticError("Restore selection must be an absolute snapshot path")
            args.extend(["--include", include])
        self._run(args)
        return staging


class ResticSFTPRepository(ResticRepository):
    """Restic repository reachable only through Lattice's strict SFTP channel."""

    def __init__(
        self,
        repository: str,
        password_file: Path,
        *,
        ssh_args: Sequence[str],
        upload_limit_kib: int | None = None,
        binary: str | None = None,
    ) -> None:
        if not isinstance(repository, str) or not repository.startswith("sftp:"):
            raise ResticError("Remote Restic repository must use the SFTP backend")
        if not ssh_args or any(not isinstance(value, str) or "\x00" in value for value in ssh_args):
            raise ResticError("Restic SFTP arguments are invalid")
        self.repository = repository
        self.password_file = validate_password_file(password_file)
        self.binary = _resolve_restic_binary(binary)
        if upload_limit_kib is not None and (
            isinstance(upload_limit_kib, bool)
            or not isinstance(upload_limit_kib, int)
            or upload_limit_kib < 1
            or upload_limit_kib > 10_000_000
        ):
            raise ResticError("Remote backup upload limit is invalid")
        options = ["-o", f"sftp.args={shlex.join(tuple(ssh_args))}"]
        if upload_limit_kib is not None:
            options.extend(["--limit-upload", str(upload_limit_kib)])
        # Restic parses sftp.args itself; subprocess is still invoked without a shell.
        self.backend_options = tuple(options)

    def initialize(self) -> None:
        self._run(["init"], timeout=120)
