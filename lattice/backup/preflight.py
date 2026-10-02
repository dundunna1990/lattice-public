"""Backup-set preflight and explosion protection."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
from typing import Iterable

from lattice.core.db import get_db_connection

GIB = 1024 ** 3
FIRST_BACKUP_CONFIRM_BYTES = 200 * GIB
GROWTH_BLOCK_DELTA_BYTES = 50 * GIB
ABSOLUTE_GROWTH_BLOCK_BYTES = 100 * GIB
NEW_DIRECTORY_BLOCK_BYTES = 30 * GIB
GROWTH_WARN_DELTA_BYTES = 10 * GIB
DEST_FREE_RATIO = 0.80
DEST_CAPACITY_RATIO = 0.50

class BackupPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupPreflightReport:
    included_bytes: int
    logical_bytes: int
    mount_targets: tuple[str, ...]
    directory_sizes: dict[str, int]
    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    requires_confirmation: bool = False
    def as_dict(self) -> dict:
        return {
            "included_bytes": self.included_bytes,
            "logical_bytes": self.logical_bytes,
            "mount_targets": list(self.mount_targets),
            "directory_sizes": dict(self.directory_sizes),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "requires_confirmation": self.requires_confirmation,
        }


def _decode_mount_path(value: str) -> str:
    replacements = {
        r"\040": " ", r"\011": "\t", r"\012": "\n", r"\134": "\\",
    }
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value


def mounts_under(source: Path, *, mountinfo: Path = Path("/proc/self/mountinfo")) -> tuple[str, ...]:
    source = source.resolve()
    found: list[str] = []
    try:
        lines = mountinfo.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BackupPreflightError(f"Could not inspect mounted filesystems: {exc}") from exc
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        target = Path(_decode_mount_path(fields[4]))
        try:
            target.relative_to(source)
        except ValueError:
            continue
        if target == source:
            continue
        found.append(str(target))
    return tuple(sorted(set(found)))
def _excluded(path: Path, patterns: tuple[str, ...]) -> bool:
    value = str(path)
    return any(value == pattern or fnmatchcase(value, pattern) for pattern in patterns)


def _has_cache_marker(path: Path) -> bool:
    if (path / ".lattice-exclude-dir").exists() or (path / "pyvenv.cfg").exists():
        return True
    tag = path / "CACHEDIR.TAG"
    try:
        if not tag.is_file():
            return False
        prefix = tag.read_bytes()[:64]
    except OSError:
        return False
    return prefix.startswith(b"Signature: 8a477f597d28d172789f06886806bc55")


def scan_source(source: Path, excludes: Iterable[Path]) -> BackupPreflightReport:
    source = source.resolve()
    try:
        source_device = source.stat().st_dev
    except OSError as exc:
        raise BackupPreflightError(f"Backup source cannot be inspected: {exc}") from exc

    patterns = tuple(str(value) for value in excludes)
    included = 0
    logical = 0
    directory_sizes: dict[str, int] = {}
    stack = [source]

    while stack:
        directory = stack.pop()
        if directory != source and _excluded(directory, patterns):
            continue
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise BackupPreflightError(f"Could not inspect backup source {directory}: {exc}") from exc
        if metadata.st_dev != source_device or _has_cache_marker(directory):
            continue
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise BackupPreflightError(f"Could not read backup source {directory}: {exc}") from exc

        for entry in entries:
            path = Path(entry.path)
            if _excluded(path, patterns):
                continue
            try:
                stat_result = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BackupPreflightError(f"Could not inspect backup source {path}: {exc}") from exc

            if entry.is_dir(follow_symlinks=False):
                if stat_result.st_dev == source_device:
                    stack.append(path)
                continue

            on_disk = max(0, int(getattr(stat_result, "st_blocks", 0))) * 512
            if on_disk == 0 and stat_result.st_size > 0:
                on_disk = int(stat_result.st_size)
            included += on_disk
            logical += max(0, int(stat_result.st_size))

            try:
                relative = path.relative_to(source)
            except ValueError:
                continue
            parts = relative.parts[:-1]
            for depth in range(1, min(len(parts), 3) + 1):
                key = str(Path(*parts[:depth]))
                directory_sizes[key] = directory_sizes.get(key, 0) + on_disk

    largest = dict(sorted(directory_sizes.items(), key=lambda item: item[1], reverse=True)[:100])
    return BackupPreflightReport(
        included_bytes=included,
        logical_bytes=logical,
        mount_targets=mounts_under(source),
        directory_sizes=largest,
    )
def _baseline(job_id: int) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM backup_preflight_state WHERE job_id=?",
            (int(job_id),),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["mount_targets"] = tuple(json.loads(data.pop("mount_targets_json") or "[]"))
        data["directory_sizes"] = dict(json.loads(data.pop("directory_sizes_json") or "{}"))
        return data
    finally:
        conn.close()


def target_capacity(job_id: int) -> tuple[int | None, int | None]:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bto.total_bytes,bto.free_bytes,bto.last_reported_at
               FROM backup_jobs bj
               LEFT JOIN backup_target_observations bto ON bto.target_id=bj.target_id
               WHERE bj.id=?""",
            (int(job_id),),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row["total_bytes"] is None or row["free_bytes"] is None:
        return None, None
    return int(row["total_bytes"]), int(row["free_bytes"])
def evaluate_preflight(
    report: BackupPreflightReport,
    *,
    previous: dict | None,
    established: bool,
    target_total_bytes: int | None,
    target_free_bytes: int | None,
    allow_large_first_backup: bool = False,
) -> BackupPreflightReport:
    blockers: list[str] = []
    warnings: list[str] = []
    confirmation = False

    previous_mounts = set(previous.get("mount_targets", ())) if previous else set()
    current_mounts = set(report.mount_targets)
    if previous is not None:
        new_mounts = current_mounts - previous_mounts
        if new_mounts:
            blockers.append("New mount under backup source: " + ", ".join(sorted(new_mounts)))
    elif current_mounts:
        if not established and not allow_large_first_backup:
            confirmation = True
        warnings.append("Initial mount layout recorded: " + ", ".join(sorted(current_mounts)))

    if established and previous is not None:
        previous_size = max(0, int(previous.get("included_bytes") or 0))
        capacity_basis = max(0, report.included_bytes - previous_size)
    else:
        capacity_basis = report.included_bytes
    if target_free_bytes is not None and capacity_basis > int(target_free_bytes * DEST_FREE_RATIO):
        blockers.append("Estimated new backup data exceeds 80% of destination free space")
    if target_total_bytes is not None and capacity_basis > int(target_total_bytes * DEST_CAPACITY_RATIO):
        blockers.append("Estimated new backup data exceeds 50% of destination capacity")

    if not established and previous is None and report.included_bytes > FIRST_BACKUP_CONFIRM_BYTES:
        if allow_large_first_backup:
            warnings.append("Large first backup explicitly confirmed by operator")
        else:
            confirmation = True
    if previous:
        old = max(0, int(previous.get("included_bytes") or 0))
        delta = report.included_bytes - old
        if old > 0 and report.included_bytes > old * 3 and delta > GROWTH_BLOCK_DELTA_BYTES:
            blockers.append("Backup set grew by more than 3x and over 50 GiB")
        if delta > ABSOLUTE_GROWTH_BLOCK_BYTES:
            blockers.append("Backup set grew by more than 100 GiB")
        if old > 0 and report.included_bytes > old * 1.5 and delta > GROWTH_WARN_DELTA_BYTES:
            warnings.append("Backup set grew by more than 1.5x and over 10 GiB")

        previous_dirs = dict(previous.get("directory_sizes", {}))
        new_large = [
            path for path, size in report.directory_sizes.items()
            if size > NEW_DIRECTORY_BLOCK_BYTES and path not in previous_dirs
        ]
        if new_large:
            blockers.append("New directory over 30 GiB: " + ", ".join(sorted(new_large)[:5]))

    return BackupPreflightReport(
        included_bytes=report.included_bytes,
        logical_bytes=report.logical_bytes,
        mount_targets=report.mount_targets,
        directory_sizes=report.directory_sizes,
        blockers=tuple(blockers),
        warnings=tuple(warnings),
        requires_confirmation=confirmation,
    )
def run_preflight(
    job_id: int,
    source: Path,
    excludes: Iterable[Path],
    *,
    established: bool,
    allow_large_first_backup: bool = False,
    target_total_bytes: int | None = None,
    target_free_bytes: int | None = None,
) -> BackupPreflightReport:
    scanned = scan_source(source, excludes)
    if target_total_bytes is None or target_free_bytes is None:
        observed_total, observed_free = target_capacity(job_id)
        target_total_bytes = target_total_bytes if target_total_bytes is not None else observed_total
        target_free_bytes = target_free_bytes if target_free_bytes is not None else observed_free
    result = evaluate_preflight(
        scanned,
        previous=_baseline(job_id),
        established=established,
        target_total_bytes=target_total_bytes,
        target_free_bytes=target_free_bytes,
        allow_large_first_backup=allow_large_first_backup,
    )
    if result.blockers:
        raise BackupPreflightError("; ".join(result.blockers))
    if result.requires_confirmation:
        raise BackupPreflightError(
            "First backup source size or mount layout requires explicit operator confirmation"
        )
    return result


def record_successful_preflight(job_id: int, report: BackupPreflightReport) -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT INTO backup_preflight_state(
                   job_id,included_bytes,logical_bytes,mount_targets_json,directory_sizes_json,
                   last_warning,updated_at)
               VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(job_id) DO UPDATE SET
                   included_bytes=excluded.included_bytes,
                   logical_bytes=excluded.logical_bytes,
                   mount_targets_json=excluded.mount_targets_json,
                   directory_sizes_json=excluded.directory_sizes_json,
                   last_warning=excluded.last_warning,
                   updated_at=CURRENT_TIMESTAMP""",
            (
                int(job_id), int(report.included_bytes), int(report.logical_bytes),
                json.dumps(list(report.mount_targets), sort_keys=True),
                json.dumps(report.directory_sizes, sort_keys=True),
                "; ".join(report.warnings)[:1000] or None,
            ),
        )
        conn.commit()
    finally:
        conn.close()
