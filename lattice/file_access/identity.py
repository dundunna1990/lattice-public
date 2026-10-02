"""Permanent local node identity for Lattice fleet membership."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import tempfile
import uuid


DEFAULT_NODE_IDENTITY_PATH = Path("/var/lib/lattice/node-identity.json")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class NodeIdentityError(RuntimeError):
    """Raised when permanent node identity cannot be read or created safely."""


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    main_user: str
    main_uid: int
    main_gid: int
    created_at: str


def _identity_path(path: Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    override = os.environ.get("LATTICE_NODE_IDENTITY_PATH")
    return Path(override) if override else DEFAULT_NODE_IDENTITY_PATH


def _validate_node_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise NodeIdentityError("Node identity contains an invalid node_id") from exc

    if parsed.version != 4:
        raise NodeIdentityError("Node identity must use a UUIDv4 node_id")

    return str(parsed)


def _validate_identity_payload(payload: object) -> NodeIdentity:
    if not isinstance(payload, dict):
        raise NodeIdentityError("Node identity has an invalid format")

    try:
        node_id = _validate_node_id(str(payload["node_id"]))
        main_user = str(payload["main_user"])
        main_uid = int(payload["main_uid"])
        main_gid = int(payload["main_gid"])
        created_at = str(payload["created_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NodeIdentityError("Node identity is missing required fields") from exc

    if not _USER_RE.fullmatch(main_user):
        raise NodeIdentityError("Node identity contains an invalid main user")
    if main_uid <= 0:
        raise NodeIdentityError("Root cannot be the Lattice main user")
    if main_gid < 0:
        raise NodeIdentityError("Node identity contains an invalid group ID")

    try:
        timestamp = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise NodeIdentityError("Node identity has an invalid creation timestamp") from exc

    if timestamp.tzinfo is None:
        raise NodeIdentityError("Node identity timestamp must include a timezone")

    return NodeIdentity(
        node_id=node_id,
        main_user=main_user,
        main_uid=main_uid,
        main_gid=main_gid,
        created_at=timestamp.isoformat(),
    )


def load_node_identity(path: Path | None = None) -> NodeIdentity | None:
    """Load the permanent local identity, refusing unsafe files."""
    identity_path = _identity_path(path)

    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(identity_path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise NodeIdentityError(f"Could not open node identity safely: {exc}") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise NodeIdentityError("Node identity is not a single regular file")
        # Production identity may be root:lattice 0640 so the
        # unprivileged Lattice daemons can read their permanent Node ID.
        # Group write/execute and all permissions for others remain forbidden.
        if metadata.st_mode & 0o027:
            raise NodeIdentityError(
                "Node identity permissions are too broad"
            )

        if metadata.st_mode & 0o040:
            try:
                lattice_gid = grp.getgrnam("lattice").gr_gid
            except KeyError as exc:
                raise NodeIdentityError(
                    "Node identity is group-readable but the lattice "
                    "group does not exist"
                ) from exc

            if metadata.st_gid != lattice_gid:
                raise NodeIdentityError(
                    "Node identity is readable by an unexpected group"
                )
        if metadata.st_size > 16384:
            raise NodeIdentityError("Node identity file is unexpectedly large")
        raw = os.read(descriptor, 16385)
    finally:
        os.close(descriptor)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NodeIdentityError("Node identity is not valid JSON") from exc

    return _validate_identity_payload(payload)


def _atomic_write_identity(path: Path, identity: NodeIdentity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(asdict(identity), handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, path)
        if path == DEFAULT_NODE_IDENTITY_PATH and os.geteuid() == 0:
            # Production daemons run as the unprivileged lattice account and
            # must be able to read the permanent node identity. Keep it
            # root-owned, grant only the lattice group read access, and deny
            # all access to other users.
            try:
                lattice_gid = grp.getgrnam("lattice").gr_gid
            except KeyError as exc:
                raise NodeIdentityError(
                    "Cannot secure production node identity because the lattice group is missing"
                ) from exc
            os.chown(path, 0, lattice_gid)
            os.chmod(path, 0o640)
        else:
            os.chmod(path, 0o600)

        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # The identity itself was already atomically committed. Some
            # filesystems do not support fsync on directories.
            pass
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def ensure_node_identity(
    main_user: str,
    *,
    path: Path | None = None,
    main_uid: int | None = None,
    main_gid: int | None = None,
) -> NodeIdentity:
    """Return the permanent identity, creating it exactly once if needed."""
    if not isinstance(main_user, str) or not _USER_RE.fullmatch(main_user):
        raise NodeIdentityError("Main user has an invalid format")

    identity_path = _identity_path(path)
    existing = load_node_identity(identity_path)

    if existing is not None:
        if existing.main_user != main_user:
            raise NodeIdentityError(
                f"Node identity belongs to main user '{existing.main_user}', "
                f"not '{main_user}'"
            )
        return existing

    if main_uid is None or main_gid is None:
        try:
            account = pwd.getpwnam(main_user)
        except KeyError as exc:
            raise NodeIdentityError(f"Main user '{main_user}' does not exist") from exc
        main_uid = account.pw_uid
        main_gid = account.pw_gid

    if main_uid <= 0:
        raise NodeIdentityError("Root cannot be the Lattice main user")
    if main_gid < 0:
        raise NodeIdentityError("Main group ID is invalid")

    identity = NodeIdentity(
        node_id=str(uuid.uuid4()),
        main_user=main_user,
        main_uid=main_uid,
        main_gid=main_gid,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    _atomic_write_identity(identity_path, identity)

    verified = load_node_identity(identity_path)
    if verified is None or verified != identity:
        raise NodeIdentityError("Node identity could not be verified after creation")

    return verified
