"""Safe user-facing file-manager integration for Lattice peers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import uuid

from lattice.file_access.identity import (
    load_node_identity,
)
from lattice.file_access.mount_plan import (
    mount_plan_path,
)


DEFAULT_MOUNT_ROOT = Path(
    "/mnt/lattice"
)
DEFAULT_STATE_PATH = Path(
    "/var/lib/lattice/desktop-links.json"
)
DEFAULT_APPLICATION_PATH = Path(
    "/usr/share/applications/lattice.desktop"
)

_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
)


class DesktopIntegrationError(
    RuntimeError
):
    pass


def _safe_json(
    path: Path,
    *,
    maximum: int = 262144,
) -> dict | None:
    flags = (
        os.O_RDONLY
        | getattr(
            os,
            "O_CLOEXEC",
            0,
        )
        | getattr(
            os,
            "O_NOFOLLOW",
            0,
        )
    )

    try:
        descriptor = os.open(
            path,
            flags,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DesktopIntegrationError(
            f"Could not safely open {path}: {exc}"
        ) from exc

    try:
        metadata = os.fstat(
            descriptor
        )

        if (
            not stat.S_ISREG(
                metadata.st_mode
            )
            or metadata.st_nlink != 1
        ):
            raise DesktopIntegrationError(
                f"{path} is unsafe"
            )

        if metadata.st_mode & 0o022:
            raise DesktopIntegrationError(
                f"{path} has unsafe permissions"
            )

        if metadata.st_size > maximum:
            raise DesktopIntegrationError(
                f"{path} is unexpectedly large"
            )

        raw = os.read(
            descriptor,
            maximum + 1,
        )
    finally:
        os.close(
            descriptor
        )

    try:
        payload = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise DesktopIntegrationError(
            f"{path} contains invalid JSON"
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise DesktopIntegrationError(
            f"{path} must contain an object"
        )

    return payload


def _atomic_json(
    path: Path,
    payload: dict,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor, temporary_name = (
        tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
    )

    temporary = Path(
        temporary_name
    )

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            os.fchmod(
                handle.fileno(),
                0o600,
            )

            json.dump(
                payload,
                handle,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.replace(
            temporary,
            path,
        )
        os.chmod(
            path,
            0o600,
        )
    finally:
        temporary.unlink(
            missing_ok=True
        )


def _local_account():
    identity = load_node_identity()

    if identity is None:
        raise DesktopIntegrationError(
            "Permanent local Node ID is missing"
        )

    try:
        account = pwd.getpwnam(
            identity.main_user
        )
    except KeyError as exc:
        raise DesktopIntegrationError(
            "Main user no longer exists"
        ) from exc

    if (
        account.pw_uid
        != identity.main_uid
        or account.pw_gid
        != identity.main_gid
        or account.pw_uid == 0
    ):
        raise DesktopIntegrationError(
            "Main user identity no longer matches"
        )

    home = Path(
        account.pw_dir
    )

    if (
        not home.is_absolute()
        or home.is_symlink()
        or not home.is_dir()
    ):
        raise DesktopIntegrationError(
            "Main user Home is unsafe"
        )

    return (
        identity,
        account,
        home,
    )


def _ensure_user_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
) -> None:
    if path.exists():
        if (
            path.is_symlink()
            or not path.is_dir()
        ):
            raise DesktopIntegrationError(
                f"Refusing unsafe directory {path}"
            )

        if path.stat().st_uid != uid:
            raise DesktopIntegrationError(
                f"{path} is not owned by the main user"
            )

        return

    path.mkdir(
        mode=0o755,
    )

    if os.geteuid() == 0:
        os.chown(
            path,
            uid,
            gid,
        )

    os.chmod(
        path,
        0o755,
    )


def _ensure_mount_target(
    node_id: str,
    *,
    mount_root: Path,
    uid: int,
    gid: int,
) -> Path:
    try:
        parsed = uuid.UUID(
            node_id
        )
    except ValueError as exc:
        raise DesktopIntegrationError(
            "Visible peer Node ID is invalid"
        ) from exc

    if parsed.version != 4:
        raise DesktopIntegrationError(
            "Visible peer Node ID must be UUIDv4"
        )

    if (
        not mount_root.is_absolute()
        or mount_root.is_symlink()
    ):
        raise DesktopIntegrationError(
            "Mount root is unsafe"
        )

    if not mount_root.exists():
        mount_root.mkdir(
            parents=True,
            mode=0o755,
        )

        if os.geteuid() == 0:
            os.chown(
                mount_root,
                0,
                0,
            )

    if not mount_root.is_dir():
        raise DesktopIntegrationError(
            "Mount root is not a directory"
        )

    target = (
        mount_root
        / str(parsed)
    )

    try:
        if target.exists():
            if (
                target.is_symlink()
                or not target.is_dir()
            ):
                raise DesktopIntegrationError(
                    "Peer mount target is unsafe"
                )
        else:
            target.mkdir(
                mode=0o755,
            )
    except DesktopIntegrationError:
        raise
    except OSError as exc:
        raise DesktopIntegrationError(
            f"Could not inspect peer mount target {target}: {exc}"
        ) from exc

    # Never mutate ownership/mode through an active FUSE/SSHFS mount.
    # Those operations would target the remote filesystem and can be
    # rejected even though the local backing directory is correct.
    if not os.path.ismount(target):
        try:
            if os.geteuid() == 0:
                os.chown(
                    target,
                    uid,
                    gid,
                )

            os.chmod(
                target,
                0o755,
            )
        except OSError as exc:
            raise DesktopIntegrationError(
                f"Could not prepare peer mount target {target}: {exc}"
            ) from exc

    return target


def _desktop_directory(
    home: Path,
    uid: int,
) -> Path | None:
    config = (
        home
        / ".config"
        / "user-dirs.dirs"
    )

    if config.exists():
        try:
            metadata = config.lstat()

            if (
                stat.S_ISREG(
                    metadata.st_mode
                )
                and metadata.st_uid == uid
                and not (
                    metadata.st_mode
                    & 0o022
                )
            ):
                for line in config.read_text(
                    encoding="utf-8"
                ).splitlines():
                    prefix = (
                        'XDG_DESKTOP_DIR="'
                    )

                    if not line.startswith(
                        prefix
                    ):
                        continue

                    value = line[
                        len(prefix):
                    ]

                    if value.endswith('"'):
                        value = value[:-1]

                    if value.startswith(
                        "$HOME/"
                    ):
                        candidate = (
                            home
                            / value[
                                len("$HOME/"):
                            ]
                        )
                    elif value == "$HOME":
                        candidate = home
                    else:
                        candidate = Path(
                            value
                        )

                    try:
                        candidate.relative_to(
                            home
                        )
                    except ValueError:
                        return None

                    if (
                        candidate.is_dir()
                        and not candidate.is_symlink()
                        and candidate.stat().st_uid
                        == uid
                    ):
                        return candidate

        except OSError:
            pass

    fallback = (
        home / "Desktop"
    )

    if (
        fallback.is_dir()
        and not fallback.is_symlink()
        and fallback.stat().st_uid
        == uid
    ):
        return fallback

    return None


def _safe_symlink(
    link: Path,
    target: Path,
) -> bool:
    desired = str(
        target
    )

    if (
        link.exists()
        or link.is_symlink()
    ):
        if not link.is_symlink():
            return False

        try:
            existing = os.readlink(
                link
            )
        except OSError:
            return False

        if existing == desired:
            return True

        return False

    temporary = (
        link.parent
        / (
            f".{link.name}."
            f"{os.getpid()}.tmp"
        )
    )

    temporary.unlink(
        missing_ok=True
    )

    os.symlink(
        desired,
        temporary,
    )

    os.replace(
        temporary,
        link,
    )

    return True


def _safe_desktop_launcher(
    shortcut: Path,
    source: Path,
    *,
    uid: int,
    gid: int,
) -> bool:
    """Install an executable user-owned desktop launcher.

    Desktop environments such as Cinnamon/Nemo may reject a .desktop
    symlink whose system application target is intentionally non-executable.
    Keep the system application 0644, but put a real 0755 copy on the user's
    Desktop so it launches without a manual "Allow Executing" step.
    """
    try:
        metadata = source.lstat()
    except OSError:
        return False

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or metadata.st_size > 65536
    ):
        return False

    try:
        payload = source.read_bytes()
    except OSError:
        return False

    if b"X-Lattice-Managed=true" not in payload:
        return False

    if shortcut.exists() or shortcut.is_symlink():
        if shortcut.is_symlink():
            try:
                if os.readlink(shortcut) == str(source):
                    shortcut.unlink()
                else:
                    return False
            except OSError:
                return False
        else:
            try:
                existing = shortcut.read_bytes()
                owner = shortcut.stat().st_uid
            except OSError:
                return False
            if owner != uid or b"X-Lattice-Managed=true" not in existing:
                return False
            if (
                existing == payload
                and (shortcut.stat().st_mode & 0o777) == 0o755
            ):
                return True

    temporary = shortcut.parent / f".{shortcut.name}.{os.getpid()}.tmp"
    temporary.unlink(missing_ok=True)
    try:
        temporary.write_bytes(payload)
        os.chmod(temporary, 0o755)
        if os.geteuid() == 0:
            os.chown(temporary, uid, gid)
        os.replace(temporary, shortcut)
        os.chmod(shortcut, 0o755)
        if os.geteuid() == 0:
            os.chown(shortcut, uid, gid)
    finally:
        temporary.unlink(missing_ok=True)

    return True


def _user_session_environment(account, home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USER"] = account.pw_name
    env["LOGNAME"] = account.pw_name
    runtime = Path(f"/run/user/{account.pw_uid}")
    if runtime.is_dir():
        env["XDG_RUNTIME_DIR"] = str(runtime)
        bus = runtime / "bus"
        if bus.exists():
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    return env


def _run_as_main_user(account, home: Path, argv: list[str]) -> subprocess.CompletedProcess:
    euid = os.geteuid()
    if euid not in {0, account.pw_uid}:
        raise DesktopIntegrationError("Cannot set desktop launcher trust as the main user")

    def demote() -> None:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)

    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=10,
        env=_user_session_environment(account, home),
        preexec_fn=demote if euid == 0 else None,
        check=False,
    )


def _trust_desktop_launcher(shortcut: Path, account, home: Path) -> None:
    gio = Path("/usr/bin/gio")
    if not gio.is_file():
        raise DesktopIntegrationError("gio is required to trust the desktop launcher")

    set_result = _run_as_main_user(
        account, home, [str(gio), "set", str(shortcut), "metadata::trusted", "true"]
    )
    if set_result.returncode != 0:
        detail = (set_result.stderr or set_result.stdout or "gio set failed").strip()
        raise DesktopIntegrationError(f"Could not trust desktop launcher: {detail}")

    info = _run_as_main_user(
        account, home, [str(gio), "info", "-a", "metadata::*", str(shortcut)]
    )
    if info.returncode != 0 or "metadata::trusted: true" not in info.stdout:
        detail = (info.stderr or info.stdout or "trusted metadata was not confirmed").strip()
        raise DesktopIntegrationError(f"Desktop launcher trust was not confirmed: {detail}")


def reconcile_desktop(
    *,
    plan_path: Path | None = None,
    mount_root: Path | None = None,
    state_path: Path | None = None,
    application_path: Path | None = None,
) -> dict:
    source = (
        plan_path
        or mount_plan_path()
    )

    payload = _safe_json(
        source
    )

    if payload is None:
        return {
            "status": "no-plan",
            "created": 0,
            "removed": 0,
            "conflicts": [],
        }

    visible = payload.get(
        "visible_peers",
        [],
    )

    if (
        not isinstance(
            visible,
            list,
        )
        or len(visible) > 32
    ):
        raise DesktopIntegrationError(
            "Visible peer registry is invalid"
        )

    (
        identity,
        account,
        home,
    ) = _local_account()

    lattice_home = (
        home / "Lattice"
    )

    _ensure_user_directory(
        lattice_home,
        uid=account.pw_uid,
        gid=account.pw_gid,
    )

    root = (
        mount_root
        or Path(
            os.environ.get(
                "LATTICE_MOUNT_ROOT",
                str(
                    DEFAULT_MOUNT_ROOT
                ),
            )
        )
    )

    registry_path = (
        state_path
        or DEFAULT_STATE_PATH
    )

    previous = (
        _safe_json(
            registry_path
        )
        or {
            "links": [],
        }
    )

    previous_links = {
        item.get("name"):
            item
        for item in previous.get(
            "links",
            [],
        )
        if isinstance(
            item,
            dict,
        )
        and isinstance(
            item.get("name"),
            str,
        )
        and isinstance(
            item.get("target"),
            str,
        )
    }

    desired_links = []
    conflicts = []
    created = 0

    for raw in visible:
        if not isinstance(
            raw,
            dict,
        ):
            raise DesktopIntegrationError(
                "Visible peer entry is invalid"
            )

        node_id = str(
            raw.get(
                "node_id",
                "",
            )
        )

        hostname = str(
            raw.get(
                "hostname",
                "",
            )
        )

        if node_id == (
            identity.node_id
        ):
            continue

        if not _HOSTNAME_RE.fullmatch(
            hostname
        ):
            raise DesktopIntegrationError(
                "Visible peer hostname is unsafe"
            )

        target = _ensure_mount_target(
            node_id,
            mount_root=root,
            uid=account.pw_uid,
            gid=account.pw_gid,
        )

        link = (
            lattice_home
            / hostname
        )

        if not _safe_symlink(
            link,
            target,
        ):
            conflicts.append(
                str(link)
            )
            continue

        if (
            hostname
            not in previous_links
        ):
            created += 1

        desired_links.append(
            {
                "name":
                    hostname,
                "node_id":
                    node_id,
                "target":
                    str(target),
            }
        )

    desired_names = {
        item["name"]
        for item in desired_links
    }

    removed = 0

    for name, previous_link in (
        previous_links.items()
    ):
        if name in desired_names:
            continue

        path = (
            lattice_home
            / name
        )

        if not path.is_symlink():
            continue

        try:
            actual_target = (
                os.readlink(
                    path
                )
            )
        except OSError:
            continue

        if actual_target != (
            previous_link[
                "target"
            ]
        ):
            continue

        path.unlink()
        removed += 1

    _atomic_json(
        registry_path,
        {
            "links":
                desired_links,
        },
    )

    # Desktop launchers are owned exclusively by deploy/install.sh.  This
    # reconciler manages shared-folder links only; creating a second legacy
    # launcher here races Ubuntu's desktop handling and can produce duplicate
    # Lattice icons after an install.

    return {
        "status":
            "ok",
        "created":
            created,
        "removed":
            removed,
        "conflicts":
            conflicts,
        "folder":
            str(
                lattice_home
            ),
    }


def remove_desktop_integration(
    *,
    state_path: Path | None = None,
    application_path: Path | None = None,
) -> None:
    try:
        (
            _identity,
            account,
            home,
        ) = _local_account()
    except DesktopIntegrationError:
        return

    lattice_home = (
        home / "Lattice"
    )

    registry_path = (
        state_path
        or DEFAULT_STATE_PATH
    )

    previous = (
        _safe_json(
            registry_path
        )
        or {
            "links": [],
        }
    )

    for item in previous.get(
        "links",
        [],
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        name = item.get(
            "name"
        )
        target = item.get(
            "target"
        )

        if (
            not isinstance(
                name,
                str,
            )
            or not isinstance(
                target,
                str,
            )
        ):
            continue

        link = (
            lattice_home
            / name
        )

        if not link.is_symlink():
            continue

        try:
            if (
                os.readlink(
                    link
                )
                == target
            ):
                link.unlink()
        except OSError:
            pass

    desktop_dir = (
        _desktop_directory(
            home,
            account.pw_uid,
        )
    )

    app = (
        application_path
        or DEFAULT_APPLICATION_PATH
    )

    if desktop_dir is not None:
        legacy_shortcut = (
            desktop_dir
            / "Lattice.desktop"
        )
        if legacy_shortcut.is_symlink():
            try:
                if os.readlink(legacy_shortcut) == str(app):
                    legacy_shortcut.unlink()
            except OSError:
                pass

        shortcut = (
            desktop_dir
            / "Lattice Nodes.desktop"
        )
        if shortcut.is_file() and not shortcut.is_symlink():
            try:
                payload = shortcut.read_bytes()
                if (
                    shortcut.stat().st_uid == account.pw_uid
                    and b"X-Lattice-Managed=true" in payload
                ):
                    shortcut.unlink()
            except OSError:
                pass

    registry_path.unlink(
        missing_ok=True
    )

    try:
        lattice_home.rmdir()
    except OSError:
        # User-created files are intentionally preserved.
        pass


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--remove",
        action="store_true",
    )

    args = parser.parse_args()

    if args.remove:
        remove_desktop_integration()
    else:
        reconcile_desktop()


if __name__ == "__main__":
    main()
