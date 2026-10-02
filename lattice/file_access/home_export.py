"""Verify and safely restore Lattice's dedicated Home export bind."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

from lattice.file_access.identity import load_node_identity
from lattice.file_access.transport import DEFAULT_CHROOT


HOME_TARGET = DEFAULT_CHROOT / "Home"
MOUNTINFO_PATH = Path("/proc/self/mountinfo")


class FileHomeExportError(RuntimeError):
    pass


def decode_mount_path(value: str) -> str:
    return (
        value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def exact_mount_source(
    target: Path,
    *,
    mountinfo_path: Path = MOUNTINFO_PATH,
) -> str | None:
    target_text = str(target.resolve())
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FileHomeExportError(f"Could not inspect mount table: {exc}") from exc

    for line in lines:
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        if decode_mount_path(fields[4]) != target_text:
            continue
        separator = fields.index("-")
        if separator + 2 >= len(fields):
            continue
        return decode_mount_path(fields[separator + 2])
    return None


def validate_home(account) -> Path:
    home = Path(account.pw_dir)
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise FileHomeExportError("Main user's Home directory is unsafe")
    metadata = home.stat()
    if metadata.st_uid != account.pw_uid:
        raise FileHomeExportError("Main user's Home has unexpected ownership")
    return home


def identity_home(identity) -> Path:
    try:
        account = pwd.getpwnam(identity.main_user)
    except KeyError as exc:
        raise FileHomeExportError("Configured main user no longer exists") from exc
    if (
        account.pw_uid != identity.main_uid
        or account.pw_gid != identity.main_gid
        or account.pw_uid == 0
    ):
        raise FileHomeExportError(
            "Main user UID/GID no longer matches permanent identity"
        )
    return validate_home(account)


def home_bind_is_current(
    identity,
    *,
    target: Path = HOME_TARGET,
    mountinfo_path: Path = MOUNTINFO_PATH,
) -> bool:
    """Return True only for an exact bind of the permanent user's real Home."""
    try:
        source = identity_home(identity)
        if exact_mount_source(target, mountinfo_path=mountinfo_path) is None:
            return False
        source_stat = source.stat()
        target_stat = target.stat()
    except (OSError, FileHomeExportError):
        return False
    return (
        source_stat.st_dev == target_stat.st_dev
        and source_stat.st_ino == target_stat.st_ino
    )


def ensure_home_bind(
    *,
    source: Path,
    target: Path,
    runner=subprocess.run,
    mountinfo_path: Path = MOUNTINFO_PATH,
) -> bool:
    """Create the expected bind if missing; refuse to replace foreign mounts."""
    if os.geteuid() != 0:
        raise FileHomeExportError("Home export repair must run as root")

    existing = exact_mount_source(target, mountinfo_path=mountinfo_path)
    if existing is not None:
        try:
            source_stat = source.stat()
            target_stat = target.stat()
        except OSError as exc:
            raise FileHomeExportError(
                f"Could not validate existing Home bind: {exc}"
            ) from exc
        if (
            source_stat.st_dev == target_stat.st_dev
            and source_stat.st_ino == target_stat.st_ino
        ):
            return False
        raise FileHomeExportError(
            "The Lattice Home target is already occupied by a different mount"
        )

    try:
        metadata = target.lstat()
    except OSError as exc:
        raise FileHomeExportError(f"Lattice Home target is unavailable: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or target.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
    ):
        raise FileHomeExportError("Lattice Home target is unsafe")

    try:
        result = runner(
            ["/usr/bin/mount", "--bind", str(source), str(target)],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FileHomeExportError(f"Could not bind Home into the file root: {exc}") from exc
    if result.returncode != 0:
        raise FileHomeExportError(
            "Could not bind Home into the file root: "
            + (result.stderr or result.stdout or "mount failed").strip()
        )

    try:
        source_stat = source.stat()
        target_stat = target.stat()
    except OSError as exc:
        raise FileHomeExportError(f"Could not verify Home bind: {exc}") from exc
    if (
        exact_mount_source(target, mountinfo_path=mountinfo_path) is None
        or source_stat.st_dev != target_stat.st_dev
        or source_stat.st_ino != target_stat.st_ino
    ):
        raise FileHomeExportError("Home bind verification failed")
    return True


def ensure_local_home_export() -> bool:
    """Root-side boot/runtime repair using the permanent local identity only."""
    identity = load_node_identity()
    if identity is None:
        raise FileHomeExportError("Permanent local Node ID is missing")
    source = identity_home(identity)
    return ensure_home_bind(source=source, target=HOME_TARGET)


def main() -> None:
    try:
        ensure_local_home_export()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
