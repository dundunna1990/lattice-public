"""System-level desired-state SSHFS mount manager for Lattice."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time
import uuid

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity
from lattice.file_access.transport import host_key_alias
from lattice.file_access.desktop import (
    DesktopIntegrationError,
    reconcile_desktop,
)
from lattice.file_access.observations import persist_local_mount_observations
from lattice.file_access.applied_state import ensure_file_transport_current
from lattice.file_access.rotation import (
    cleanup_completed_local_rotation as cleanup_file_rotation,
    confirm_local_promotion_ready as confirm_file_promotion_ready,
    ensure_rotation_staged_if_due as ensure_file_rotation_staged,
    finalize_master_rotation as finalize_file_rotation,
    process_master_rotation_proposal as process_file_rotation_proposal,
    promote_local_rotation_if_requested as promote_file_rotation,
    record_promote_request as record_file_promote_request,
    rotation_promotion_request_for as file_rotation_promotion_request,
)
from lattice.wizard.lifecycle import current_role


logger = logging.getLogger(__name__)

DEFAULT_MOUNT_ROOT = Path("/mnt/lattice")
DEFAULT_PLAN_PATH = Path("/var/lib/lattice/mount-plans.json")
DEFAULT_CLIENT_KEY = Path(
    "/etc/lattice/file-ssh/client_ed25519"
)
DEFAULT_KNOWN_HOSTS = Path(
    "/etc/lattice/file-ssh/known_hosts"
)

SSHFS_BINARY = "/usr/bin/sshfs"
STAT_BINARY = "/usr/bin/stat"
FUSERMOUNT_BINARY = "/usr/bin/fusermount3"

_USER_RE = re.compile(
    r"^[a-z_][a-z0-9_-]{0,31}$"
)


class MountManagerError(RuntimeError):
    """Raised when Lattice cannot safely reconcile a peer mount."""


@dataclass(frozen=True)
class PeerMountPlan:
    node_id: str
    hostname: str
    ip: str
    remote_user: str
    local_uid: int
    local_gid: int
    port: int = 22022
    routes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            node = uuid.UUID(self.node_id)
        except (
            ValueError,
            TypeError,
            AttributeError,
        ) as exc:
            raise MountManagerError(
                "Peer Node ID is invalid"
            ) from exc

        if node.version != 4:
            raise MountManagerError(
                "Peer Node ID must be UUIDv4"
            )

        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise MountManagerError(
                "Peer IP address is invalid"
            ) from exc

        if (
            not self.hostname
            or "\n" in self.hostname
            or "\r" in self.hostname
        ):
            raise MountManagerError(
                "Peer hostname is invalid"
            )

        if not _USER_RE.fullmatch(
            self.remote_user
        ):
            raise MountManagerError(
                "Peer file user is invalid"
            )

        if (
            isinstance(self.local_uid, bool)
            or not isinstance(self.local_uid, int)
            or self.local_uid <= 0
        ):
            raise MountManagerError(
                "Local UID is invalid"
            )

        if (
            isinstance(self.local_gid, bool)
            or not isinstance(self.local_gid, int)
            or self.local_gid < 0
        ):
            raise MountManagerError(
                "Local GID is invalid"
            )

        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise MountManagerError(
                "Peer file port is invalid"
            )

        normalized_routes = []
        for route in self.routes:
            try:
                address = ipaddress.ip_address(route)
            except ValueError as exc:
                raise MountManagerError("Peer alternate route is invalid") from exc
            private_lan = any(
                address in ipaddress.ip_network(network)
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
            if address.version != 4 or not private_lan:
                raise MountManagerError("Peer alternate route must be private IPv4")
            normalized_routes.append(str(address))
        object.__setattr__(self, "routes", tuple(dict.fromkeys(normalized_routes)))


@dataclass(frozen=True)
class MountEntry:
    mount_point: str
    filesystem_type: str
    source: str


def _mount_root() -> Path:
    value = os.environ.get(
        "LATTICE_MOUNT_ROOT"
    )
    return (
        Path(value)
        if value
        else DEFAULT_MOUNT_ROOT
    )


def _plan_path() -> Path:
    value = os.environ.get(
        "LATTICE_MOUNT_PLAN_PATH"
    )
    return (
        Path(value)
        if value
        else DEFAULT_PLAN_PATH
    )


def _client_key() -> Path:
    value = os.environ.get(
        "LATTICE_FILE_CLIENT_KEY"
    )
    return (
        Path(value)
        if value
        else DEFAULT_CLIENT_KEY
    )


def _known_hosts() -> Path:
    value = os.environ.get(
        "LATTICE_FILE_KNOWN_HOSTS"
    )
    return (
        Path(value)
        if value
        else DEFAULT_KNOWN_HOSTS
    )


def mount_path_for(
    node_id: str,
    *,
    root: Path | None = None,
) -> Path:
    try:
        parsed = uuid.UUID(node_id)
    except (
        ValueError,
        TypeError,
        AttributeError,
    ) as exc:
        raise MountManagerError(
            "Mount Node ID is invalid"
        ) from exc

    if parsed.version != 4:
        raise MountManagerError(
            "Mount Node ID must be UUIDv4"
        )

    base = root or _mount_root()

    if not base.is_absolute():
        raise MountManagerError(
            "Lattice mount root must be absolute"
        )

    return base / str(parsed)


def bounded_retry_seconds(
    failure_count: int,
    *,
    initial: float,
    maximum: float,
) -> float:
    if failure_count <= 0:
        return 0.0

    delay = initial * (
        2 ** (failure_count - 1)
    )

    return min(
        float(maximum),
        float(delay),
    )


def build_sshfs_command(
    plan: PeerMountPlan,
    *,
    mount_root: Path | None = None,
    client_key: Path | None = None,
    known_hosts: Path | None = None,
) -> list[str]:
    target = mount_path_for(
        plan.node_id,
        root=mount_root,
    )

    key = client_key or _client_key()
    hosts = known_hosts or _known_hosts()

    for path, label in (
        (key, "client key"),
        (hosts, "known-hosts file"),
    ):
        if (
            not path.is_absolute()
            or "\n" in str(path)
            or "\r" in str(path)
        ):
            raise MountManagerError(
                f"SSHFS {label} path is unsafe"
            )

    source = (
        f"{plan.remote_user}@"
        f"{plan.ip}:/Home"
    )

    return [
        SSHFS_BINARY,
        source,
        str(target),

        "-o",
        f"port={plan.port}",

        "-o",
        f"IdentityFile={key}",

        "-o",
        "IdentitiesOnly=yes",

        "-o",
        "BatchMode=yes",

        "-o",
        "NumberOfPasswordPrompts=0",

        "-o",
        "StrictHostKeyChecking=yes",

        "-o",
        f"UserKnownHostsFile={hosts}",

        "-o",
        "GlobalKnownHostsFile=/dev/null",

        "-o",
        (
            "HostKeyAlias="
            + host_key_alias(
                plan.node_id
            )
        ),

        "-o",
        "ConnectTimeout=5",

        "-o",
        "ConnectionAttempts=1",

        "-o",
        "ServerAliveInterval=10",

        "-o",
        "ServerAliveCountMax=2",

        "-o",
        "reconnect",

        "-o",
        "cache=no",

        "-o",
        "allow_other",

        "-o",
        "default_permissions",

        "-o",
        f"uid={plan.local_uid}",

        "-o",
        f"gid={plan.local_gid}",

        "-o",
        "umask=0022",
    ]


def _decode_mount_field(
    value: str,
) -> str:
    return (
        value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def find_mount_entry(
    mount_path: Path,
    mountinfo: str,
) -> MountEntry | None:
    target = str(
        mount_path.absolute()
    )

    for line in mountinfo.splitlines():
        fields = line.split()

        if len(fields) < 10:
            continue

        try:
            separator = fields.index("-")
        except ValueError:
            continue

        if separator + 2 >= len(fields):
            continue

        point = _decode_mount_field(
            fields[4]
        )

        if point != target:
            continue

        return MountEntry(
            mount_point=point,
            filesystem_type=fields[
                separator + 1
            ],
            source=_decode_mount_field(
                fields[separator + 2]
            ),
        )

    return None


def is_lattice_sshfs_mount(
    mount_path: Path,
    entry: MountEntry,
    *,
    mount_root: Path | None = None,
) -> bool:
    root = mount_root or _mount_root()

    try:
        expected = mount_path_for(
            mount_path.name,
            root=root,
        )
    except MountManagerError:
        return False

    if expected != mount_path:
        return False

    if entry.mount_point != str(
        mount_path.absolute()
    ):
        return False

    return (
        entry.filesystem_type.startswith(
            "fuse.sshfs"
        )
        and entry.source.endswith(
            ":/Home"
        )
    )


def _safe_read_json(
    path: Path,
    *,
    maximum: int = 262144,
) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    try:
        descriptor = os.open(
            path,
            flags,
        )
    except OSError as exc:
        raise MountManagerError(
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
            raise MountManagerError(
                f"{path} is not a single regular file"
            )

        if metadata.st_mode & 0o022:
            raise MountManagerError(
                f"{path} is writable by group or others"
            )

        if metadata.st_size > maximum:
            raise MountManagerError(
                f"{path} is unexpectedly large"
            )

        raw = os.read(
            descriptor,
            maximum + 1,
        )
    finally:
        os.close(descriptor)

    try:
        payload = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise MountManagerError(
            f"{path} is invalid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise MountManagerError(
            f"{path} must contain a JSON object"
        )

    return payload


def _peer_is_pinned(
    node_id: str,
    *,
    known_hosts: Path | None = None,
) -> bool:
    path = known_hosts or _known_hosts()

    try:
        text = path.read_text(
            encoding="utf-8"
        )
    except OSError:
        return False

    alias = host_key_alias(
        node_id
    )

    for line in text.splitlines():
        fields = line.split()

        if len(fields) < 3:
            continue

        aliases = fields[0].split(",")

        if (
            alias in aliases
            and fields[1]
            == "ssh-ed25519"
        ):
            return True

    return False


def load_mount_plans(
    path: Path | None = None,
) -> list[PeerMountPlan]:
    source = path or _plan_path()

    if not source.exists():
        return []

    payload = _safe_read_json(
        source
    )

    peers = payload.get(
        "peers",
        [],
    )

    if not isinstance(peers, list):
        raise MountManagerError(
            "Mount plan peers must be a list"
        )

    identity = load_node_identity()

    if identity is None:
        raise MountManagerError(
            "Local permanent Node ID is missing"
        )

    plans: list[PeerMountPlan] = []
    seen: set[str] = set()

    for item in peers:
        if not isinstance(item, dict):
            raise MountManagerError(
                "Mount plan peer is invalid"
            )

        plan = PeerMountPlan(
            node_id=str(
                item.get(
                    "node_id",
                    "",
                )
            ),
            hostname=str(
                item.get(
                    "hostname",
                    "",
                )
            ),
            ip=str(
                item.get(
                    "ip",
                    "",
                )
            ),
            remote_user=str(
                item.get(
                    "remote_user",
                    "",
                )
            ),
            local_uid=identity.main_uid,
            local_gid=identity.main_gid,
            port=int(
                item.get(
                    "port",
                    22022,
                )
            ),
            routes=tuple(
                str(route.get("ip"))
                for route in item.get("routes", [])
                if isinstance(route, dict) and route.get("ip") is not None
            ),
        )

        if plan.node_id == identity.node_id:
            continue

        if plan.node_id in seen:
            raise MountManagerError(
                "Mount plan contains duplicate Node ID"
            )

        if not _peer_is_pinned(
            plan.node_id
        ):
            raise MountManagerError(
                "Mount plan contains a peer "
                "without a pinned file host key"
            )

        seen.add(
            plan.node_id
        )
        plans.append(
            plan
        )

    return plans


def load_retired_node_ids(
    path: Path | None = None,
) -> list[str]:
    source = path or _plan_path()

    if not source.exists():
        return []

    payload = _safe_read_json(
        source
    )

    raw = payload.get(
        "retired_node_ids",
        [],
    )

    if (
        not isinstance(raw, list)
        or len(raw) > 128
        or not all(
            isinstance(value, str)
            for value in raw
        )
        or len(set(raw)) != len(raw)
    ):
        raise MountManagerError(
            "Mount plan retired Node IDs are invalid"
        )

    normalized = []

    for value in raw:
        try:
            parsed = uuid.UUID(
                value
            )
        except ValueError as exc:
            raise MountManagerError(
                "Retired Node ID is invalid"
            ) from exc

        if parsed.version != 4:
            raise MountManagerError(
                "Retired Node ID must be UUIDv4"
            )

        normalized.append(
            str(parsed)
        )

    return sorted(
        normalized
    )


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _iso(
    value: datetime,
) -> str:
    return value.astimezone(
        timezone.utc
    ).isoformat()


def _parse_time(
    value: str | None,
) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            value
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def _local_fleet_role(conn) -> str | None:
    """Read the local role from permanent identity + committed fleet state."""
    try:
        identity = load_node_identity()
    except Exception:
        return None
    if identity is None:
        return None
    try:
        row = conn.execute(
            """SELECT role FROM fleet_nodes
               WHERE node_id = ? AND membership_state = 'active'
               LIMIT 1""",
            (identity.node_id,),
        ).fetchone()
    except Exception:
        return None
    return str(row["role"]) if row is not None else None


def _peer_file_export_healthy(
    conn,
    peer_node_id: str,
    *,
    now: datetime,
) -> bool:
    """Master-side authenticated proof that a Worker's Home export is live."""
    row = conn.execute(
        """SELECT s.status, s.last_reported_at
           FROM fleet_nodes f
           JOIN services s ON s.worker_id = f.worker_id
           WHERE f.node_id = ?
             AND f.role = 'worker'
             AND f.membership_state = 'active'
             AND s.name = 'file_export'
           LIMIT 1""",
        (peer_node_id,),
    ).fetchone()
    if row is None or str(row["status"]) != "healthy":
        return False
    reported_at = _parse_time(row["last_reported_at"])
    if reported_at is None:
        return False
    return now - reported_at < timedelta(seconds=30)


def _ensure_rows(
    conn,
    peer_node_id: str,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO mount_preferences (
            peer_node_id,
            desired_state
        )
        VALUES (?, 'mounted')
        """,
        (peer_node_id,),
    )

    conn.execute(
        """
        INSERT OR IGNORE INTO mount_state (
            peer_node_id,
            state
        )
        VALUES (?, 'unknown')
        """,
        (peer_node_id,),
    )


def _update_state(
    conn,
    peer_node_id: str,
    *,
    now: datetime,
    **fields,
) -> None:
    allowed = {
        "state",
        "mount_path",
        "failure_count",
        "last_probe_at",
        "last_success_at",
        "next_retry_at",
        "error_code",
        "error_message",
        "problem_since",
        "alert_id",
    }

    invalid = (
        set(fields) - allowed
    )

    if invalid:
        raise MountManagerError(
            "Invalid mount state field"
        )

    fields["updated_at"] = _iso(
        now
    )

    assignments = ", ".join(
        f"{name} = ?"
        for name in fields
    )

    values = list(
        fields.values()
    )

    values.append(
        peer_node_id
    )

    conn.execute(
        f"""
        UPDATE mount_state
        SET {assignments}
        WHERE peer_node_id = ?
        """,
        values,
    )


def set_mount_preference(
    peer_node_id: str,
    desired_state: str,
) -> None:
    mount_path_for(
        peer_node_id
    )

    if desired_state not in {
        "mounted",
        "paused",
    }:
        raise MountManagerError(
            "Mount preference must be mounted or paused"
        )

    conn = get_db_connection()

    try:
        _ensure_rows(
            conn,
            peer_node_id,
        )

        now = _utc_now()

        conn.execute(
            """
            UPDATE mount_preferences
            SET desired_state = ?,
                paused_at = ?,
                updated_at = ?
            WHERE peer_node_id = ?
            """,
            (
                desired_state,
                (
                    _iso(now)
                    if desired_state
                    == "paused"
                    else None
                ),
                _iso(now),
                peer_node_id,
            ),
        )

        if desired_state == "mounted":
            _update_state(
                conn,
                peer_node_id,
                now=now,
                state="unknown",
                failure_count=0,
                next_retry_at=None,
                error_code=None,
                error_message=None,
            )

        conn.commit()

    finally:
        conn.close()


def _reconcile_file_key_rotation() -> None:
    identity = load_node_identity()
    role = current_role()
    proposal = ensure_file_rotation_staged()
    if identity is not None and role == "master" and proposal is not None:
        process_file_rotation_proposal(identity.node_id, proposal)

    # Ensure this host actually applies the current signed file policy.
    ensure_file_transport_current()

    if identity is not None and role == "master":
        request = file_rotation_promotion_request(identity.node_id)
        if request is not None:
            record_file_promote_request(request)

    promoted = promote_file_rotation()
    if promoted is not None:
        restarted = subprocess.run(
            ["systemctl", "restart", "lattice-file-sshd.service"],
            capture_output=True, text=True, timeout=20,
        )
        if restarted.returncode != 0:
            detail = (restarted.stderr or restarted.stdout or "systemd error").strip()
            raise MountManagerError(f"Could not activate promoted file host key: {detail}")
        confirm_file_promotion_ready()
        if identity is not None and role == "master":
            finalize_file_rotation(identity.node_id, promoted)
        ensure_file_transport_current()

    cleanup_file_rotation()


class MountManager:
    def __init__(
        self,
        *,
        runner=subprocess.run,
        mountinfo_reader=None,
        clock=_utc_now,
        sleeper=time.sleep,
        mount_root: Path | None = None,
    ):
        self.runner = runner
        self.mountinfo_reader = (
            mountinfo_reader
            or self._read_mountinfo
        )
        self.clock = clock
        self.sleeper = sleeper
        self.mount_root = (
            mount_root
            or _mount_root()
        )

        self._wake_event = (
            threading.Event()
        )

    def wake(self) -> None:
        """Wake the reconciliation loop immediately."""
        self._wake_event.set()

    def _wait_for_next_cycle(
        self,
        seconds: float,
    ) -> None:
        self._wake_event.wait(
            timeout=max(
                0.0,
                float(seconds),
            )
        )
        self._wake_event.clear()

    @staticmethod
    def _read_mountinfo() -> str:
        try:
            return Path(
                "/proc/self/mountinfo"
            ).read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise MountManagerError(
                f"Could not inspect mount table: {exc}"
            ) from exc

    def _run(
        self,
        command: list[str],
        *,
        timeout: int,
    ):
        try:
            return self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise
        except OSError as exc:
            raise MountManagerError(
                f"Could not execute {command[0]}: {exc}"
            ) from exc

    def _ensure_mountpoint(
        self,
        plan: PeerMountPlan,
    ) -> Path:
        root = self.mount_root
        target = mount_path_for(
            plan.node_id,
            root=root,
        )

        if root.exists():
            if (
                root.is_symlink()
                or not root.is_dir()
            ):
                raise MountManagerError(
                    "Lattice mount root is unsafe"
                )
        else:
            root.mkdir(
                parents=True,
                mode=0o755,
            )

        if target.exists():
            if (
                target.is_symlink()
                or not target.is_dir()
            ):
                raise MountManagerError(
                    "Peer mount path is unsafe"
                )
        else:
            target.mkdir(
                mode=0o755,
            )

        if os.geteuid() == 0:
            os.chown(
                root,
                0,
                0,
            )
            os.chmod(
                root,
                0o755,
            )

            os.chown(
                target,
                plan.local_uid,
                plan.local_gid,
            )
            os.chmod(
                target,
                0o755,
            )

        return target

    def _probe(
        self,
        path: Path,
    ) -> tuple[bool, str | None]:
        try:
            result = self._run(
                [
                    STAT_BINARY,
                    "-c",
                    "%d",
                    str(path),
                ],
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return (
                False,
                "probe_timeout",
            )
        except MountManagerError:
            return (
                False,
                "probe_exec_error",
            )

        if result.returncode != 0:
            return (
                False,
                "probe_failed",
            )

        return (
            True,
            None,
        )

    def _unmount_if_owned(
        self,
        path: Path,
    ) -> bool:
        entry = find_mount_entry(
            path,
            self.mountinfo_reader(),
        )

        if entry is None:
            return True

        if not is_lattice_sshfs_mount(
            path,
            entry,
            mount_root=self.mount_root,
        ):
            return False

        try:
            result = self._run(
                [
                    FUSERMOUNT_BINARY,
                    "-u",
                    "-z",
                    str(path),
                ],
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            return False

        return result.returncode == 0

    def _failure(
        self,
        conn,
        plan: PeerMountPlan,
        *,
        now: datetime,
        current_failures: int,
        state: str,
        code: str,
        message: str,
    ) -> None:
        config = load_config()

        failures = (
            current_failures + 1
        )

        delay = bounded_retry_seconds(
            failures,
            initial=(
                config
                .file_access
                .retry_initial_seconds
            ),
            maximum=(
                config
                .file_access
                .retry_max_seconds
            ),
        )

        retry_at = now + timedelta(
            seconds=delay
        )

        current = conn.execute(
            """
            SELECT problem_since
            FROM mount_state
            WHERE peer_node_id = ?
            """,
            (plan.node_id,),
        ).fetchone()

        problem_since = (
            current["problem_since"]
            if (
                current is not None
                and current["problem_since"]
            )
            else _iso(now)
        )

        _update_state(
            conn,
            plan.node_id,
            now=now,
            state=state,
            mount_path=str(
                mount_path_for(
                    plan.node_id,
                    root=self.mount_root,
                )
            ),
            failure_count=failures,
            next_retry_at=_iso(
                retry_at
            ),
            error_code=code,
            error_message=message[:500],
            problem_since=problem_since,
        )

    @staticmethod
    def _worker_id_for_node(
        conn,
        node_id: str,
    ) -> int | None:
        row = conn.execute(
            """
            SELECT worker_id
            FROM fleet_nodes
            WHERE node_id = ?
            """,
            (node_id,),
        ).fetchone()

        if (
            row is None
            or row["worker_id"] is None
        ):
            return None

        return int(
            row["worker_id"]
        )

    def _resolve_mount_alert(
        self,
        conn,
        node_id: str,
        hostname: str,
        *,
        now: datetime,
        reason: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT alert_id
            FROM mount_state
            WHERE peer_node_id = ?
            """,
            (node_id,),
        ).fetchone()

        alert_id = (
            row["alert_id"]
            if row is not None
            else None
        )

        if alert_id is not None:
            worker_id = (
                self._worker_id_for_node(
                    conn,
                    node_id,
                )
            )

            cursor = conn.execute(
                """
                INSERT INTO events (
                    timestamp,
                    worker_id,
                    type,
                    severity,
                    message,
                    details
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(now),
                    worker_id,
                    "file_access.mount_recovered",
                    "ok",
                    (
                        "Lattice file access recovered "
                        f"for {hostname}."
                    ),
                    json.dumps(
                        {
                            "peer_node_id":
                                node_id,
                            "reason":
                                reason,
                        },
                        sort_keys=True,
                    ),
                ),
            )

            resolution_event_id = (
                cursor.lastrowid
            )

            conn.execute(
                """
                UPDATE alerts
                SET resolved_at = ?,
                    resolution_event_id = ?
                WHERE id = ?
                  AND resolved_at IS NULL
                """,
                (
                    _iso(now),
                    resolution_event_id,
                    alert_id,
                ),
            )

        conn.execute(
            """
            UPDATE mount_state
            SET problem_since = NULL,
                alert_id = NULL
            WHERE peer_node_id = ?
            """,
            (node_id,),
        )

    def _sync_persistent_alert(
        self,
        conn,
        plan: PeerMountPlan,
    ) -> None:
        row = conn.execute(
            """
            SELECT
                state,
                problem_since,
                alert_id,
                error_code,
                error_message
            FROM mount_state
            WHERE peer_node_id = ?
            """,
            (plan.node_id,),
        ).fetchone()

        if row is None:
            return

        now = self.clock()

        problem_states = {
            "offline",
            "stale",
            "mount_problem",
            "reconnecting",
        }

        if row["state"] not in problem_states:
            if (
                row["problem_since"]
                is not None
                or row["alert_id"]
                is not None
            ):
                self._resolve_mount_alert(
                    conn,
                    plan.node_id,
                    plan.hostname,
                    now=now,
                    reason=row["state"],
                )
            return

        problem_since = _parse_time(
            row["problem_since"]
        )

        if problem_since is None:
            problem_since = now

            conn.execute(
                """
                UPDATE mount_state
                SET problem_since = ?
                WHERE peer_node_id = ?
                """,
                (
                    _iso(problem_since),
                    plan.node_id,
                ),
            )

        if row["alert_id"] is not None:
            return

        config = load_config()

        age = (
            now - problem_since
        ).total_seconds()

        if age < (
            config
            .file_access
            .persistent_alert_seconds
        ):
            return

        worker_id = (
            self._worker_id_for_node(
                conn,
                plan.node_id,
            )
        )

        title = (
            "File access unavailable: "
            + plan.hostname
        )

        message = (
            f"Lattice has been unable to maintain "
            f"file access to {plan.hostname} for "
            f"approximately {int(age)} seconds."
        )

        event = conn.execute(
            """
            INSERT INTO events (
                timestamp,
                worker_id,
                type,
                severity,
                message,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                _iso(now),
                worker_id,
                "file_access.mount_persistent",
                "error",
                message,
                json.dumps(
                    {
                        "peer_node_id":
                            plan.node_id,
                        "hostname":
                            plan.hostname,
                        "state":
                            row["state"],
                        "error_code":
                            row["error_code"],
                        "error_message":
                            row["error_message"],
                        "problem_since":
                            _iso(problem_since),
                    },
                    sort_keys=True,
                ),
            ),
        )

        event_id = event.lastrowid

        alert = conn.execute(
            """
            INSERT INTO alerts (
                worker_id,
                severity,
                title,
                message,
                trigger_event_id,
                fired_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                worker_id,
                "error",
                title,
                message,
                event_id,
                _iso(now),
            ),
        )

        conn.execute(
            """
            UPDATE mount_state
            SET alert_id = ?
            WHERE peer_node_id = ?
            """,
            (
                alert.lastrowid,
                plan.node_id,
            ),
        )

    def _retirement_problem(
        self,
        conn,
        node_id: str,
        *,
        now: datetime,
        code: str,
        message: str,
    ) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO mount_state (
                peer_node_id,
                state
            )
            VALUES (?, 'unknown')
            """,
            (node_id,),
        )

        _update_state(
            conn,
            node_id,
            now=now,
            state="mount_problem",
            mount_path=str(
                mount_path_for(
                    node_id,
                    root=self.mount_root,
                )
            ),
            error_code=code,
            error_message=message,
        )

    def retire_node(
        self,
        conn,
        node_id: str,
    ) -> bool:
        """Detach and retire one cryptographically revoked peer."""
        now = self.clock()

        target = mount_path_for(
            node_id,
            root=self.mount_root,
        )

        entry = find_mount_entry(
            target,
            self.mountinfo_reader(),
        )

        if entry is not None:
            if not is_lattice_sshfs_mount(
                target,
                entry,
                mount_root=self.mount_root,
            ):
                self._retirement_problem(
                    conn,
                    node_id,
                    now=now,
                    code="retired_foreign_mount",
                    message=(
                        "Revoked peer path is occupied "
                        "by a non-Lattice mount"
                    ),
                )
                return False

            if not self._unmount_if_owned(
                target
            ):
                self._retirement_problem(
                    conn,
                    node_id,
                    now=now,
                    code="retired_unmount_failed",
                    message=(
                        "Could not detach revoked "
                        "Lattice SSHFS mount"
                    ),
                )
                return False

            remaining = find_mount_entry(
                target,
                self.mountinfo_reader(),
            )

            if remaining is not None:
                self._retirement_problem(
                    conn,
                    node_id,
                    now=now,
                    code="retired_mount_still_present",
                    message=(
                        "Revoked Lattice mount is "
                        "still present after detach"
                    ),
                )
                return False

        if (
            target.exists()
            or target.is_symlink()
        ):
            if (
                target.is_symlink()
                or not target.is_dir()
            ):
                self._retirement_problem(
                    conn,
                    node_id,
                    now=now,
                    code="retired_path_unsafe",
                    message=(
                        "Revoked peer path is not "
                        "a safe directory"
                    ),
                )
                return False

            try:
                target.rmdir()
            except OSError as exc:
                self._retirement_problem(
                    conn,
                    node_id,
                    now=now,
                    code=(
                        "retired_directory_not_empty"
                    ),
                    message=(
                        "Revoked peer directory was "
                        f"not empty: {exc}"
                    ),
                )
                return False

        self._resolve_mount_alert(
            conn,
            node_id,
            node_id,
            now=now,
            reason="revoked",
        )

        conn.execute(
            """
            DELETE FROM mount_state
            WHERE peer_node_id = ?
            """,
            (node_id,),
        )

        conn.execute(
            """
            DELETE FROM mount_preferences
            WHERE peer_node_id = ?
            """,
            (node_id,),
        )

        return True

    def reconcile_peer(
        self,
        conn,
        plan: PeerMountPlan,
    ) -> None:
        now = self.clock()

        _ensure_rows(
            conn,
            plan.node_id,
        )

        preference = conn.execute(
            """
            SELECT desired_state
            FROM mount_preferences
            WHERE peer_node_id = ?
            """,
            (plan.node_id,),
        ).fetchone()

        state_row = conn.execute(
            """
            SELECT
                state,
                failure_count,
                next_retry_at
            FROM mount_state
            WHERE peer_node_id = ?
            """,
            (plan.node_id,),
        ).fetchone()

        desired = (
            preference["desired_state"]
            if preference
            else "mounted"
        )

        failures = int(
            state_row["failure_count"]
            if state_row
            else 0
        )

        target = mount_path_for(
            plan.node_id,
            root=self.mount_root,
        )

        entry = find_mount_entry(
            target,
            self.mountinfo_reader(),
        )

        if desired == "paused":
            if entry is not None:
                if not is_lattice_sshfs_mount(
                    target,
                    entry,
                    mount_root=self.mount_root,
                ):
                    _update_state(
                        conn,
                        plan.node_id,
                        now=now,
                        state="mount_problem",
                        mount_path=str(
                            target
                        ),
                        error_code=(
                            "foreign_mount"
                        ),
                        error_message=(
                            "Mount path is occupied "
                            "by a non-Lattice mount"
                        ),
                    )
                    return

                if not self._unmount_if_owned(
                    target
                ):
                    _update_state(
                        conn,
                        plan.node_id,
                        now=now,
                        state="mount_problem",
                        error_code=(
                            "pause_unmount_failed"
                        ),
                        error_message=(
                            "Could not unmount "
                            "paused Lattice peer"
                        ),
                    )
                    return

            _update_state(
                conn,
                plan.node_id,
                now=now,
                state="paused",
                mount_path=str(
                    target
                ),
                failure_count=0,
                next_retry_at=None,
                error_code=None,
                error_message=None,
                problem_since=None,
            )
            return

        # On the Master, a local SSHFS mount is not enough.  Require a fresh,
        # authenticated Worker heartbeat proving that its dedicated /Home export
        # is still the real permanent user's Home bind.  Never keep serving a
        # known-empty/broken export merely because stat(2) succeeds locally.
        if _local_fleet_role(conn) == "master":
            export_ok = _peer_file_export_healthy(
                conn, plan.node_id, now=now
            )
            if not export_ok and (
                entry is None
                or is_lattice_sshfs_mount(
                    target, entry, mount_root=self.mount_root
                )
            ):
                # Detaching a known-bad export is a safety action, not a retry.
                # Never leave it mounted merely because reconnect backoff is active.
                if entry is not None and not self._unmount_if_owned(target):
                    self._failure(
                        conn,
                        plan,
                        now=now,
                        current_failures=failures,
                        state="stale",
                        code="remote_export_unhealthy",
                        message=(
                            "Worker file export is unhealthy and the existing "
                            "Lattice mount could not be detached"
                        ),
                    )
                    return
                if entry is None:
                    retry_at = _parse_time(
                        state_row["next_retry_at"] if state_row else None
                    )
                    if retry_at is not None and retry_at > now:
                        return
                self._failure(
                    conn,
                    plan,
                    now=now,
                    current_failures=failures,
                    state="reconnecting",
                    code="remote_export_unhealthy",
                    message=(
                        "Worker has not supplied fresh proof that its Home "
                        "export is healthy"
                    ),
                )
                return

        if entry is not None:
            if not is_lattice_sshfs_mount(
                target,
                entry,
                mount_root=self.mount_root,
            ):
                _update_state(
                    conn,
                    plan.node_id,
                    now=now,
                    state="mount_problem",
                    mount_path=str(
                        target
                    ),
                    error_code="foreign_mount",
                    error_message=(
                        "Lattice mount path is "
                        "occupied by another filesystem"
                    ),
                )
                return

            healthy, probe_error = (
                self._probe(
                    target
                )
            )

            if healthy:
                _update_state(
                    conn,
                    plan.node_id,
                    now=now,
                    state="mounted",
                    mount_path=str(
                        target
                    ),
                    failure_count=0,
                    last_probe_at=_iso(
                        now
                    ),
                    last_success_at=_iso(
                        now
                    ),
                    next_retry_at=None,
                    error_code=None,
                    error_message=None,
                    problem_since=None,
                )
                return

            if not self._unmount_if_owned(
                target
            ):
                self._failure(
                    conn,
                    plan,
                    now=now,
                    current_failures=failures,
                    state="stale",
                    code=(
                        probe_error
                        or "stale_mount"
                    ),
                    message=(
                        "Stale Lattice SSHFS mount "
                        "could not be detached"
                    ),
                )
                return

            self._failure(
                conn,
                plan,
                now=now,
                current_failures=failures,
                state="reconnecting",
                code=(
                    probe_error
                    or "stale_mount"
                ),
                message=(
                    "Stale Lattice SSHFS mount "
                    "was detached"
                ),
            )
            return

        retry_at = _parse_time(
            (
                state_row[
                    "next_retry_at"
                ]
                if state_row
                else None
            )
        )

        if (
            retry_at is not None
            and retry_at > now
        ):
            return

        try:
            target = self._ensure_mountpoint(
                plan
            )
        except MountManagerError as exc:
            self._failure(
                conn,
                plan,
                now=now,
                current_failures=failures,
                state="mount_problem",
                code="mountpoint_unsafe",
                message=str(exc),
            )
            return

        _update_state(
            conn,
            plan.node_id,
            now=now,
            state=(
                "connecting"
                if failures == 0
                else "reconnecting"
            ),
            mount_path=str(
                target
            ),
            error_code=None,
            error_message=None,
        )

        candidate_ips = list(dict.fromkeys((plan.ip, *plan.routes)))
        result = None
        route_errors: list[str] = []
        timed_out = 0
        for candidate_ip in candidate_ips:
            candidate_plan = replace(plan, ip=candidate_ip)
            command = build_sshfs_command(
                candidate_plan,
                mount_root=self.mount_root,
            )
            try:
                attempted = self._run(command, timeout=20)
            except subprocess.TimeoutExpired:
                timed_out += 1
                route_errors.append(f"{candidate_ip}: connection timed out")
                continue
            except MountManagerError as exc:
                self._failure(
                    conn, plan, now=now, current_failures=failures,
                    state="mount_problem", code="sshfs_exec_error", message=str(exc),
                )
                return
            if attempted.returncode == 0:
                result = attempted
                if candidate_ip != plan.ip:
                    logger.info(
                        "File access to %s recovered through alternate LAN route %s",
                        plan.hostname, candidate_ip,
                    )
                break
            detail = (attempted.stderr or attempted.stdout or "SSHFS failed").strip()
            route_errors.append(f"{candidate_ip}: {detail[:300]}")

        if result is None:
            code = "connect_timeout" if timed_out == len(candidate_ips) else "sshfs_failed"
            detail = "; ".join(route_errors) or "No private LAN route is currently available"
            self._failure(
                conn, plan, now=now, current_failures=failures, state="offline",
                code=code, message=detail,
            )
            return

        mounted = find_mount_entry(
            target,
            self.mountinfo_reader(),
        )

        if (
            mounted is None
            or not is_lattice_sshfs_mount(
                target,
                mounted,
                mount_root=self.mount_root,
            )
        ):
            self._failure(
                conn,
                plan,
                now=now,
                current_failures=failures,
                state="mount_problem",
                code="mount_missing",
                message=(
                    "SSHFS exited successfully "
                    "but the expected Lattice "
                    "mount did not appear"
                ),
            )
            return

        healthy, probe_error = self._probe(
            target
        )

        if not healthy:
            self._unmount_if_owned(
                target
            )

            self._failure(
                conn,
                plan,
                now=now,
                current_failures=failures,
                state="reconnecting",
                code=(
                    probe_error
                    or "probe_failed"
                ),
                message=(
                    "New SSHFS mount did not "
                    "pass its health probe"
                ),
            )
            return

        _update_state(
            conn,
            plan.node_id,
            now=now,
            state="mounted",
            mount_path=str(
                target
            ),
            failure_count=0,
            last_probe_at=_iso(
                now
            ),
            last_success_at=_iso(
                now
            ),
            next_retry_at=None,
            error_code=None,
            error_message=None,
            problem_since=None,
        )

    def reconcile_once(
        self,
        plans: list[
            PeerMountPlan
        ],
        *,
        retired_node_ids: list[str] | None = None,
    ) -> None:
        conn = get_db_connection()

        try:
            for node_id in (
                retired_node_ids
                or []
            ):
                try:
                    self.retire_node(
                        conn,
                        node_id,
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    logger.exception(
                        "Revoked mount cleanup "
                        "failed for %s",
                        node_id,
                    )

            for plan in plans:
                try:
                    self.reconcile_peer(
                        conn,
                        plan,
                    )

                    self._sync_persistent_alert(
                        conn,
                        plan,
                    )

                    conn.commit()
                except Exception:
                    conn.rollback()
                    logger.exception(
                        "Mount reconciliation "
                        "failed for %s",
                        plan.node_id,
                    )
        finally:
            conn.close()

    def run_forever(self) -> None:
        while True:
            config = load_config()

            if not config.file_access.enabled:
                self._wait_for_next_cycle(
                    config
                    .file_access
                    .probe_interval_seconds
                )
                continue

            try:
                try:
                    _reconcile_file_key_rotation()
                except Exception:
                    logger.exception("File key rotation reconciliation failed")

                plans = load_mount_plans()
                retired = load_retired_node_ids()

                try:
                    reconcile_desktop(
                        mount_root=self.mount_root,
                    )
                except DesktopIntegrationError:
                    logger.exception(
                        "Could not reconcile Lattice "
                        "desktop/file-manager entries"
                    )

                active_ids = {
                    plan.node_id
                    for plan in plans
                }

                if active_ids.intersection(
                    retired
                ):
                    raise MountManagerError(
                        "Mount plan marks an active peer "
                        "as retired"
                    )

                self.reconcile_once(
                    plans,
                    retired_node_ids=retired,
                )

                try:
                    persist_local_mount_observations()
                except Exception:
                    logger.exception("Could not persist local fleet mount observations")
            except MountManagerError:
                logger.exception(
                    "Could not load safe "
                    "Lattice mount plans"
                )

            self._wait_for_next_cycle(
                config
                .file_access
                .probe_interval_seconds
            )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    manager = MountManager()

    def _wake_manager(
        _signum,
        _frame,
    ):
        manager.wake()

    signal.signal(
        signal.SIGUSR1,
        _wake_manager,
    )

    try:
        manager.run_forever()
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
