"""Authenticated locator plans for Lattice peer mounts.

Cryptographic identity comes from the already-verified fleet manifest.
This file supplies only the current network locator for those identities.
"""

from __future__ import annotations

import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile

from lattice.core.lan_routes import (
    LanRouteError, normalize_reported_routes,
)

from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
)
from lattice.file_access.sync import (
    FleetSyncError,
    get_cached_signed_manifest,
)


DEFAULT_MOUNT_PLAN_PATH = Path(
    "/var/lib/lattice/mount-plans.json"
)
DEFAULT_MOUNT_PLAN_LOCK_PATH = Path(
    "/run/lattice/mount-plans.lock"
)

_LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class MountPlanError(RuntimeError):
    """Raised when peer locator state cannot be safely trusted."""


def _daemon_account_ids() -> tuple[int, int]:
    try:
        account = pwd.getpwnam("lattice")
        group = grp.getgrnam("lattice")
    except KeyError as exc:
        raise MountPlanError("Lattice daemon account is missing") from exc
    return account.pw_uid, group.gr_gid


def _normalize_default_owner_fd(descriptor: int) -> None:
    """Root-created shared artifacts must remain reopenable by the daemon."""
    if os.geteuid() != 0:
        return
    uid, gid = _daemon_account_ids()
    os.fchown(descriptor, uid, gid)


def mount_plan_path() -> Path:
    override = os.environ.get(
        "LATTICE_MOUNT_PLAN_PATH"
    )

    return (
        Path(override)
        if override
        else DEFAULT_MOUNT_PLAN_PATH
    )


def normalize_lan_ip(
    value: object,
) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise MountPlanError("Peer locator IP is invalid") from exc
    if address.version != 4:
        raise MountPlanError("Phase-two LAN mounting currently requires IPv4")
    if not any(address in network for network in _LAN_NETWORKS):
        raise MountPlanError("Peer locator is outside the private LAN ranges")
    return str(address)


def _safe_existing_json(
    path: Path,
) -> dict | None:
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
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MountPlanError(
            f"Could not safely open existing mount plan: {exc}"
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
            raise MountPlanError(
                "Existing mount plan is not a single regular file"
            )

        if metadata.st_mode & 0o022:
            raise MountPlanError(
                "Existing mount plan permissions are unsafe"
            )

        if metadata.st_size > 262144:
            raise MountPlanError(
                "Existing mount plan is unexpectedly large"
            )

        raw = os.read(
            descriptor,
            262145,
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
        raise MountPlanError(
            "Existing mount plan is invalid JSON"
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise MountPlanError(
            "Existing mount plan must be an object"
        )

    return payload


def _atomic_write(
    path: Path,
    payload: dict,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
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
            if path == DEFAULT_MOUNT_PLAN_PATH:
                _normalize_default_owner_fd(handle.fileno())

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

        if (
            path.exists()
            or path.is_symlink()
        ):
            metadata = path.lstat()

            if (
                not stat.S_ISREG(
                    metadata.st_mode
                )
                or metadata.st_nlink != 1
            ):
                raise MountPlanError(
                    "Refusing to replace unsafe mount plan path"
                )

        os.replace(
            temporary,
            path,
        )
        os.chmod(
            path,
            0o600,
        )

    except Exception:
        temporary.unlink(
            missing_ok=True
        )
        raise


def validate_mount_plan(
    manifest_payload: object,
    plan_payload: object,
) -> dict:
    """Bind every locator to an identity in one signed generation."""
    try:
        manifest = normalize_manifest(
            manifest_payload
        )
    except FleetManifestError as exc:
        raise MountPlanError(
            f"Fleet manifest is invalid: {exc}"
        ) from exc

    if not isinstance(
        plan_payload,
        dict,
    ):
        raise MountPlanError(
            "Mount plan must be an object"
        )

    generation = plan_payload.get(
        "generation"
    )

    if (
        isinstance(generation, bool)
        or not isinstance(
            generation,
            int,
        )
        or generation < 1
    ):
        raise MountPlanError(
            "Mount plan generation is invalid"
        )

    if generation != manifest[
        "generation"
    ]:
        raise MountPlanError(
            "Mount plan generation does not match "
            "the signed fleet generation"
        )

    raw_peers = plan_payload.get(
        "peers"
    )

    if (
        not isinstance(raw_peers, list)
        or len(raw_peers) > 32
    ):
        raise MountPlanError(
            "Mount plan peers must be a bounded list"
        )

    raw_retired = plan_payload.get(
        "retired_node_ids",
        [],
    )

    if (
        not isinstance(raw_retired, list)
        or len(raw_retired) > 128
        or not all(
            isinstance(value, str)
            for value in raw_retired
        )
        or len(set(raw_retired))
        != len(raw_retired)
    ):
        raise MountPlanError(
            "Mount plan retired Node IDs are invalid"
        )

    expected_retired = sorted(
        manifest["revoked"]
    )

    if sorted(raw_retired) != expected_retired:
        raise MountPlanError(
            "Mount plan retired Node IDs do not match "
            "the signed fleet revocations"
        )

    expected_visible_peers = sorted(
        [
            {
                "node_id":
                    member["node_id"],
                "hostname":
                    member["hostname"],
            }
            for member in manifest[
                "members"
            ]
        ],
        key=lambda item: item[
            "node_id"
        ],
    )

    raw_visible_peers = (
        plan_payload.get(
            "visible_peers"
        )
    )

    if raw_visible_peers is not None:
        if (
            not isinstance(
                raw_visible_peers,
                list,
            )
            or len(raw_visible_peers) > 32
        ):
            raise MountPlanError(
                "Visible peer registry is invalid"
            )

        normalized_visible = []

        for raw_visible in (
            raw_visible_peers
        ):
            if not isinstance(
                raw_visible,
                dict,
            ):
                raise MountPlanError(
                    "Visible peer registry is invalid"
                )

            normalized_visible.append(
                {
                    "node_id":
                        str(
                            raw_visible.get(
                                "node_id",
                                "",
                            )
                        ),
                    "hostname":
                        str(
                            raw_visible.get(
                                "hostname",
                                "",
                            )
                        ),
                }
            )

        normalized_visible.sort(
            key=lambda item: item[
                "node_id"
            ]
        )

        if (
            normalized_visible
            != expected_visible_peers
        ):
            raise MountPlanError(
                "Visible peer registry does not match "
                "the signed fleet"
            )

    members = {
        member["node_id"]: member
        for member in manifest[
            "members"
        ]
    }

    seen: set[str] = set()
    peers: list[dict] = []

    for raw in raw_peers:
        if not isinstance(
            raw,
            dict,
        ):
            raise MountPlanError(
                "Mount plan peer is invalid"
            )

        node_id = str(
            raw.get(
                "node_id",
                "",
            )
        )

        if node_id in seen:
            raise MountPlanError(
                "Mount plan contains a duplicate Node ID"
            )

        member = members.get(
            node_id
        )

        if member is None:
            raise MountPlanError(
                "Mount plan contains a Node ID "
                "outside the signed fleet"
            )

        hostname = raw.get(
            "hostname"
        )
        remote_user = raw.get(
            "remote_user"
        )

        if hostname != member[
            "hostname"
        ]:
            raise MountPlanError(
                "Mount locator hostname does not match "
                "the signed member"
            )

        if remote_user != member[
            "main_user"
        ]:
            raise MountPlanError(
                "Mount locator user does not match "
                "the signed member"
            )

        ip = normalize_lan_ip(
            raw.get("ip")
        )
        normalized_routes = None
        if raw.get("routes") is not None:
            try:
                normalized_routes = normalize_reported_routes(raw.get("routes"))
            except LanRouteError as exc:
                raise MountPlanError(f"Peer route list is invalid: {exc}") from exc
            if not normalized_routes or ip not in {route["ip"] for route in normalized_routes}:
                raise MountPlanError("Primary peer IP is not present in its route list")

        port = raw.get(
            "port",
            22022,
        )

        if (
            isinstance(port, bool)
            or not isinstance(
                port,
                int,
            )
            or not 1 <= port <= 65535
        ):
            raise MountPlanError(
                "Mount locator port is invalid"
            )

        seen.add(
            node_id
        )

        normalized_peer = {
            "node_id": node_id,
            "hostname": member["hostname"],
            "ip": ip,
            "remote_user": member["main_user"],
            "port": port,
        }
        if normalized_routes is not None:
            normalized_peer["routes"] = normalized_routes
        peers.append(normalized_peer)

    peers.sort(
        key=lambda item: item[
            "node_id"
        ]
    )

    return {
        "generation":
            generation,
        "peers":
            peers,
        "visible_peers":
            expected_visible_peers,
        "retired_node_ids":
            expected_retired,
    }


def build_mount_plan(
    manifest_payload: object,
    locators: dict[str, object],
    *,
    port: int = 22022,
) -> dict:
    """Build locators using identity fields only from the signed manifest."""
    try:
        manifest = normalize_manifest(
            manifest_payload
        )
    except FleetManifestError as exc:
        raise MountPlanError(
            f"Fleet manifest is invalid: {exc}"
        ) from exc

    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise MountPlanError(
            "File transport port is invalid"
        )

    peers = []

    for member in manifest[
        "members"
    ]:
        raw_ip = locators.get(
            member["node_id"]
        )

        if raw_ip is None:
            continue

        route_list = raw_ip if isinstance(raw_ip, list) else None
        if route_list is not None:
            try:
                routes = normalize_reported_routes(route_list)
            except LanRouteError:
                routes = []
            if not routes:
                continue
            ip = routes[0]["ip"]
        else:
            try:
                ip = normalize_lan_ip(raw_ip)
            except MountPlanError:
                # A missing/invalid locator does not remove the identity from
                # the fleet. It simply means there is no usable route yet.
                continue
            routes = None

        peer = {
            "node_id": member["node_id"],
            "hostname": member["hostname"],
            "ip": ip,
            "remote_user": member["main_user"],
            "port": port,
        }
        if routes is not None:
            peer["routes"] = routes
        peers.append(peer)

    return validate_mount_plan(
        manifest,
        {
            "generation":
                manifest[
                    "generation"
                ],
            "peers":
                peers,
            "retired_node_ids":
                list(
                    manifest[
                        "revoked"
                    ]
                ),
        },
    )


def write_mount_plan(
    manifest_payload: object,
    plan_payload: object,
    *,
    path: Path | None = None,
) -> bool:
    """Atomically replace the local locator file when it actually changed."""
    normalized = validate_mount_plan(
        manifest_payload,
        plan_payload,
    )

    destination = (
        path
        or mount_plan_path()
    )

    lock_override = os.environ.get("LATTICE_MOUNT_PLAN_LOCK_PATH")
    lock_path = (
        Path(lock_override)
        if lock_override
        else (
            DEFAULT_MOUNT_PLAN_LOCK_PATH
            if destination == DEFAULT_MOUNT_PLAN_PATH
            else destination.with_name(f".{destination.name}.lock")
        )
    )
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    lock_fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
        0o640,
    )
    try:
        if lock_path == DEFAULT_MOUNT_PLAN_LOCK_PATH:
            _normalize_default_owner_fd(lock_fd)
            os.fchmod(lock_fd, 0o640)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        existing = _safe_existing_json(destination)

        if existing == normalized:
            return False

        if isinstance(existing, dict):
            old_generation = existing.get("generation")
            new_generation = normalized.get("generation")
            if (
                isinstance(old_generation, int)
                and not isinstance(old_generation, bool)
                and isinstance(new_generation, int)
                and not isinstance(new_generation, bool)
                and old_generation > new_generation
            ):
                return False

        _atomic_write(
            destination,
            normalized,
        )
        return True
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def apply_remote_mount_plan(
    plan_payload: object,
) -> bool:
    """Worker-side apply using the locally cached verified fleet manifest."""
    try:
        cached = get_cached_signed_manifest()
    except FleetSyncError as exc:
        raise MountPlanError(
            f"Could not read verified fleet state: {exc}"
        ) from exc

    if cached is None:
        raise MountPlanError(
            "No verified fleet generation is cached"
        )

    manifest, _signature = cached

    return write_mount_plan(
        manifest,
        plan_payload,
    )
