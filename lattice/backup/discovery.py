"""Read-only discovery of local filesystems eligible for backup targets."""
from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from typing import Callable


class BackupDiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscoveredStorage:
    name: str
    device: str
    filesystem_uuid: str
    filesystem_type: str
    mountpoint: str
    size_bytes: int
    removable: bool


def _flatten(devices: list[dict]) -> list[dict]:
    result: list[dict] = []
    for item in devices:
        result.append(item)
        children = item.get("children")
        if isinstance(children, list):
            result.extend(_flatten(children))
    return result


def discover_storage(*, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[DiscoveredStorage]:
    """Return mounted, UUID-bearing filesystems without changing the host."""
    try:
        completed = runner(
            ["lsblk", "--json", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,UUID,MOUNTPOINTS,SIZE,RM"],
            check=True,
            text=True,
            capture_output=True,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise BackupDiscoveryError(f"Could not inspect local storage: {exc}") from exc

    devices = payload.get("blockdevices") if isinstance(payload, dict) else None
    if not isinstance(devices, list):
        raise BackupDiscoveryError("lsblk returned an invalid storage inventory")

    found: list[DiscoveredStorage] = []
    for item in _flatten(devices):
        if not isinstance(item, dict) or item.get("type") not in {"part", "crypt", "lvm"}:
            continue
        uuid = item.get("uuid")
        fstype = item.get("fstype")
        mountpoints = item.get("mountpoints")
        if not isinstance(uuid, str) or not uuid.strip() or not isinstance(fstype, str) or not fstype.strip():
            continue
        if not isinstance(mountpoints, list):
            mountpoints = [item.get("mountpoint")]
        mountpoint = next((str(v) for v in mountpoints if isinstance(v, str) and v.startswith("/")), None)
        if mountpoint is None:
            continue
        try:
            size = int(item.get("size") or 0)
            removable = bool(int(item.get("rm") or 0))
        except (TypeError, ValueError):
            continue
        found.append(DiscoveredStorage(
            name=str(item.get("name") or item.get("path") or "storage"),
            device=str(item.get("path") or ""),
            filesystem_uuid=uuid.strip(),
            filesystem_type=fstype.strip(),
            mountpoint=mountpoint,
            size_bytes=max(0, size),
            removable=removable,
        ))
    return sorted(found, key=lambda value: (not value.removable, value.mountpoint.casefold()))


def local_storage_candidate_payload(observer_node_id: str) -> list[dict]:
    """Return bounded read-only storage discovery suitable for heartbeat reporting."""
    return [
        {
            "observer_node_id": observer_node_id,
            "name": item.name,
            "device": item.device,
            "filesystem_uuid": item.filesystem_uuid,
            "filesystem_type": item.filesystem_type,
            "mountpoint": item.mountpoint,
            "size_bytes": item.size_bytes,
            "removable": item.removable,
        }
        for item in discover_storage()[:64]
    ]


def normalize_storage_candidates(payload: object, observer_node_id: str) -> list[dict]:
    if payload is None:
        return []
    if not isinstance(payload, list) or len(payload) > 64:
        raise BackupDiscoveryError("Backup storage candidates must be a bounded list")
    result: list[dict] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise BackupDiscoveryError("Backup storage candidate must be an object")
        if raw.get("observer_node_id") != observer_node_id:
            raise BackupDiscoveryError("Backup storage candidate has the wrong observer Node ID")
        uuid_value = raw.get("filesystem_uuid")
        name = raw.get("name")
        device = raw.get("device")
        fstype = raw.get("filesystem_type")
        mountpoint = raw.get("mountpoint")
        size = raw.get("size_bytes")
        removable = raw.get("removable")
        if (
            not isinstance(uuid_value, str)
            or not uuid_value.strip()
            or len(uuid_value) > 128
            or uuid_value in seen
        ):
            raise BackupDiscoveryError("Backup storage filesystem identity is invalid or duplicated")
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise BackupDiscoveryError("Backup storage name is invalid")
        if not isinstance(device, str) or len(device) > 256:
            raise BackupDiscoveryError("Backup storage device is invalid")
        if not isinstance(fstype, str) or not fstype.strip() or len(fstype) > 64:
            raise BackupDiscoveryError("Backup storage filesystem type is invalid")
        if not isinstance(mountpoint, str) or not mountpoint.startswith("/") or len(mountpoint) > 4096:
            raise BackupDiscoveryError("Backup storage mountpoint is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise BackupDiscoveryError("Backup storage size is invalid")
        if not isinstance(removable, bool):
            raise BackupDiscoveryError("Backup storage removable flag is invalid")
        seen.add(uuid_value)
        result.append({
            "observer_node_id": observer_node_id,
            "name": name.strip(),
            "device": device,
            "filesystem_uuid": uuid_value.strip(),
            "filesystem_type": fstype.strip(),
            "mountpoint": mountpoint,
            "size_bytes": size,
            "removable": removable,
        })
    return result
