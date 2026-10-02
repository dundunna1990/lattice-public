"""Root-side application of one cryptographically trusted file-transport state."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import grp
import stat
import subprocess
import tempfile

from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import (
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
    verify_manifest,
)
from lattice.file_access.applied_state import FILE_APPLIED_PATH, write_applied_state
from lattice.file_access.home_export import (
    FileHomeExportError,
    decode_mount_path as _decode_mount_path,
    ensure_home_bind,
    exact_mount_source,
    validate_home,
)
from lattice.file_access.transport import (
    DEFAULT_AUTHORIZED_KEYS,
    DEFAULT_CHROOT,
    DEFAULT_HOST_KEY,
    DEFAULT_KNOWN_HOSTS,
    render_authorized_keys,
    render_known_hosts,
    render_sshd_config,
)


REQUEST_PATH = Path(
    "/var/lib/lattice/file-transport-request.json"
)
FILE_SSH_DIR = Path("/etc/lattice/file-ssh")
SSHD_CONFIG = FILE_SSH_DIR / "sshd_config"
HOME_TARGET = DEFAULT_CHROOT / "Home"
LEGACY_HOME_TARGET = Path("/var/lib/lattice/file-root/Home")

WORKER_BOOTSTRAP = Path(
    "/etc/lattice/fleet/bootstrap.json"
)
MASTER_SIGNING_PUBLIC = Path(
    "/etc/lattice/fleet-signing/fleet_signing_ed25519.pub"
)


class FileTransportApplyError(RuntimeError):
    pass


def _safe_read(
    path: Path,
    *,
    allowed_uids: set[int],
    maximum: int,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    descriptor = os.open(path, flags)

    try:
        metadata = os.fstat(descriptor)

        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise FileTransportApplyError(
                f"{path} is not a single regular file"
            )

        if metadata.st_uid not in allowed_uids:
            raise FileTransportApplyError(
                f"{path} has unexpected ownership"
            )

        if metadata.st_mode & 0o022:
            raise FileTransportApplyError(
                f"{path} is writable by group or others"
            )

        if metadata.st_size > maximum:
            raise FileTransportApplyError(
                f"{path} is unexpectedly large"
            )

        return os.read(
            descriptor,
            maximum + 1,
        )
    finally:
        os.close(descriptor)


def _safe_json(
    path: Path,
    *,
    allowed_uids: set[int],
    maximum: int,
) -> dict:
    try:
        raw = _safe_read(
            path,
            allowed_uids=allowed_uids,
            maximum=maximum,
        )
        payload = json.loads(
            raw.decode("utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise FileTransportApplyError(
            f"Could not safely read {path}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise FileTransportApplyError(
            f"{path} does not contain a JSON object"
        )

    return payload


def _safe_public_key(path: Path) -> str:
    try:
        raw = _safe_read(
            path,
            allowed_uids={0},
            maximum=4096,
        )
        return validate_ed25519_public_key(
            raw.decode("utf-8").strip()
        )
    except Exception as exc:
        if isinstance(
            exc,
            FileTransportApplyError,
        ):
            raise
        raise FileTransportApplyError(
            f"Could not safely read {path}: {exc}"
        ) from exc


def _trusted_signing_key() -> str:
    if WORKER_BOOTSTRAP.exists():
        payload = _safe_json(
            WORKER_BOOTSTRAP,
            allowed_uids={0},
            maximum=32768,
        )

        try:
            return validate_ed25519_public_key(
                payload[
                    "fleet_signing_public_key"
                ]
            )
        except Exception as exc:
            raise FileTransportApplyError(
                "Worker fleet signing key is invalid"
            ) from exc

    if MASTER_SIGNING_PUBLIC.exists():
        return _safe_public_key(
            MASTER_SIGNING_PUBLIC
        )

    raise FileTransportApplyError(
        "No pinned fleet signing public key exists"
    )


def _local_member(
    manifest: dict,
    node_id: str,
):
    member = next(
        (
            item
            for item in manifest["members"]
            if item["node_id"] == node_id
        ),
        None,
    )

    if member is None:
        raise FileTransportApplyError(
            "This computer is not active in the supplied fleet generation"
        )

    return member


def _read_local_public_key(name: str) -> str:
    path = FILE_SSH_DIR / f"{name}.pub"

    try:
        raw = _safe_read(
            path,
            allowed_uids={0},
            maximum=4096,
        )
        return validate_ed25519_public_key(
            raw.decode("utf-8").strip()
        )
    except Exception as exc:
        if isinstance(
            exc,
            FileTransportApplyError,
        ):
            raise
        raise FileTransportApplyError(
            f"Local key {name} is invalid: {exc}"
        ) from exc


def _atomic_write(
    path: Path,
    content: str,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )

    temporary = Path(temporary_name)

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.chown(
            temporary,
            uid,
            gid,
        )
        os.chmod(
            temporary,
            mode,
        )

        if path.exists() or path.is_symlink():
            metadata = path.lstat()

            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise FileTransportApplyError(
                    f"Refusing to replace unsafe path {path}"
                )

        os.replace(
            temporary,
            path,
        )
    finally:
        temporary.unlink(
            missing_ok=True
        )


def _exact_mount_source(target: Path) -> str | None:
    try:
        return exact_mount_source(target)
    except FileHomeExportError as exc:
        raise FileTransportApplyError(str(exc)) from exc


def _detach_legacy_home_bind(*, source: Path) -> None:
    existing = _exact_mount_source(LEGACY_HOME_TARGET)
    if existing is None:
        return

    try:
        source_stat = source.stat()
        target_stat = LEGACY_HOME_TARGET.stat()
    except OSError as exc:
        raise FileTransportApplyError(
            f"Could not validate legacy Home bind: {exc}"
        ) from exc

    if (
        source_stat.st_dev != target_stat.st_dev
        or source_stat.st_ino != target_stat.st_ino
    ):
        raise FileTransportApplyError(
            "Legacy Lattice Home target is occupied by an unexpected mount"
        )

    try:
        result = subprocess.run(
            ["/usr/bin/umount", str(LEGACY_HOME_TARGET)],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FileTransportApplyError(
            f"Could not detach legacy Home bind: {exc}"
        ) from exc

    if result.returncode != 0:
        raise FileTransportApplyError(
            "Could not detach legacy Home bind: "
            + (result.stderr or result.stdout or "umount failed").strip()
        )

    if _exact_mount_source(LEGACY_HOME_TARGET) is not None:
        raise FileTransportApplyError("Legacy Home bind remained attached after unmount")


def _ensure_home_bind(*, source: Path, target: Path) -> None:
    try:
        ensure_home_bind(source=source, target=target)
    except FileHomeExportError as exc:
        raise FileTransportApplyError(str(exc)) from exc


def _validate_home(account) -> Path:
    try:
        return validate_home(account)
    except FileHomeExportError as exc:
        raise FileTransportApplyError(str(exc)) from exc

def apply_request(
    request_path: Path = REQUEST_PATH,
) -> None:
    if os.geteuid() != 0:
        raise FileTransportApplyError(
            "File transport reconciliation must run as root"
        )

    if request_path != REQUEST_PATH:
        raise FileTransportApplyError(
            "Only the fixed Lattice transport request path is accepted"
        )

    try:
        lattice = pwd.getpwnam("lattice")
        lattice_group = grp.getgrnam(
            "lattice"
        )
    except KeyError as exc:
        raise FileTransportApplyError(
            "The lattice service account is unavailable"
        ) from exc

    request = _safe_json(
        request_path,
        allowed_uids={
            0,
            lattice.pw_uid,
        },
        maximum=524288,
    )

    try:
        manifest = normalize_manifest(
            request["manifest"]
        )
        signature = str(
            request["signature"]
        )
    except (
        KeyError,
        FleetManifestError,
    ) as exc:
        raise FileTransportApplyError(
            "Transport request contains an invalid fleet manifest"
        ) from exc

    signing_key = _trusted_signing_key()

    if not verify_manifest(
        manifest,
        signature,
        signing_key,
    ):
        raise FileTransportApplyError(
            "Transport request fleet signature is invalid"
        )

    identity = load_node_identity()

    if identity is None:
        raise FileTransportApplyError(
            "Permanent local Node ID is missing"
        )

    member = _local_member(
        manifest,
        identity.node_id,
    )

    if member["main_user"] != identity.main_user:
        raise FileTransportApplyError(
            "Fleet manifest main user does not match local identity"
        )

    client_public = _read_local_public_key(
        "client_ed25519"
    )
    host_public = _read_local_public_key(
        "host_ed25519"
    )

    allowed_clients = [member["file_public_key"]]
    allowed_hosts = [member["file_host_public_key"]]
    if member.get("file_next_public_key"):
        allowed_clients.append(member["file_next_public_key"])
    if member.get("file_next_host_public_key"):
        allowed_hosts.append(member["file_next_host_public_key"])
    client_identity = client_public.split()[:2]
    host_identity = host_public.split()[:2]
    if client_identity not in [value.split()[:2] for value in allowed_clients]:
        raise FileTransportApplyError(
            "Fleet manifest contains the wrong local client key"
        )
    if host_identity not in [value.split()[:2] for value in allowed_hosts]:
        raise FileTransportApplyError(
            "Fleet manifest contains the wrong local host key"
        )

    try:
        account = pwd.getpwnam(
            identity.main_user
        )
    except KeyError as exc:
        raise FileTransportApplyError(
            "Configured main user no longer exists"
        ) from exc

    if (
        account.pw_uid != identity.main_uid
        or account.pw_gid != identity.main_gid
        or account.pw_uid == 0
    ):
        raise FileTransportApplyError(
            "Main user UID/GID no longer matches permanent identity"
        )

    home = _validate_home(
        account
    )

    DEFAULT_CHROOT.mkdir(
        parents=True,
        exist_ok=True,
    )
    os.chown(
        DEFAULT_CHROOT,
        0,
        0,
    )
    os.chmod(
        DEFAULT_CHROOT,
        0o755,
    )

    HOME_TARGET.mkdir(
        exist_ok=True,
    )

    # Before it becomes a bind mount, the empty target itself is root-owned.
    if _exact_mount_source(
        HOME_TARGET
    ) is None:
        os.chown(
            HOME_TARGET,
            0,
            0,
        )
        os.chmod(
            HOME_TARGET,
            0o755,
        )

    FILE_SSH_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    os.chown(
        FILE_SSH_DIR,
        0,
        lattice_group.gr_gid,
    )
    os.chmod(
        FILE_SSH_DIR,
        0o750,
    )

    client_private = (
        FILE_SSH_DIR
        / "client_ed25519"
    )
    host_private = (
        FILE_SSH_DIR
        / "host_ed25519"
    )

    for path in (
        client_private,
        host_private,
    ):
        if (
            not path.is_file()
            or path.is_symlink()
        ):
            raise FileTransportApplyError(
                f"Required private key is unsafe or missing: {path}"
            )

    os.chown(
        client_private,
        0,
        0,
    )
    os.chmod(
        client_private,
        0o600,
    )

    os.chown(
        host_private,
        0,
        0,
    )
    os.chmod(
        host_private,
        0o600,
    )

    authorized = render_authorized_keys(
        manifest,
        identity.node_id,
    )
    known_hosts = render_known_hosts(
        manifest,
        identity.node_id,
    )
    sshd_config = render_sshd_config(
        main_user=identity.main_user,
    )

    _atomic_write(
        DEFAULT_AUTHORIZED_KEYS,
        authorized,
        mode=0o640,
        uid=0,
        gid=account.pw_gid,
    )

    _atomic_write(
        DEFAULT_KNOWN_HOSTS,
        known_hosts,
        mode=0o640,
        uid=0,
        gid=lattice_group.gr_gid,
    )

    _atomic_write(
        SSHD_CONFIG,
        sshd_config,
        mode=0o600,
        uid=0,
        gid=0,
    )

    _detach_legacy_home_bind(source=home)

    _ensure_home_bind(
        source=home,
        target=HOME_TARGET,
    )

    try:
        result = subprocess.run(
            [
                "/usr/sbin/sshd",
                "-t",
                "-f",
                str(SSHD_CONFIG),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise FileTransportApplyError(
            f"Could not validate dedicated sshd configuration: {exc}"
        ) from exc

    if result.returncode != 0:
        raise FileTransportApplyError(
            "Dedicated sshd configuration failed validation: "
            + (result.stderr or result.stdout or "unknown sshd error").strip()
        )

    write_applied_state(
        FILE_APPLIED_PATH,
        node_id=identity.node_id,
        generation=int(manifest["generation"]),
    )
    request_path.unlink()


def main() -> None:
    import sys

    try:
        apply_request()
    except Exception as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
