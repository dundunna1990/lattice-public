"""Root-only automatic repair for machine-owned Lattice IPv4 addresses."""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from lattice.core.config import load_config
from lattice.file_access.identity import load_node_identity
from lattice.ip_change.setup import (
    StaticIPError, StaticIPPlan, apply_static_ip,
    is_address_available, restore_connection,
)
from lattice.ip_change.state import (
    clear_expected_network, read_expected_network, read_state,
    write_expected_network, write_state,
)
POLICY_PATH = Path("/etc/lattice/network-policy.json")
PRIVATE_STATUS_PATH = Path("/var/lib/lattice-root/network-reconcile-status.json")
HEALTH_STATUS_PATH = Path("/run/lattice/network-health.json")
LOCK_PATH = Path("/run/lattice/network-reconcile.lock")
ROLE_PATH = Path("/etc/lattice/role")
WORKER_ASSIGNMENT_RESULT = Path("/var/lib/lattice/network-assignment-result.json")
DRIFT_GRACE_SECONDS = 60
REPAIR_COOLDOWN_SECONDS = 300
NETWORK_HEALTH_STALE_SECONDS = 60
_SCHEMA_VERSION = 1
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


logger = logging.getLogger(__name__)


class NetworkReconcileError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _run(command, **kwargs):
    return subprocess.run(command, **kwargs)


def _checked(command, runner=_run, timeout=20):
    try:
        result = runner(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkReconcileError(f"Could not run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise NetworkReconcileError(f"{command[0]} failed: {detail}")
    return result

def _atomic_json(path: Path, payload: dict, mode: int = 0o644, gid: int | None = None) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0 if gid is None else gid)
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _safe_root_json(path: Path, *, max_bytes: int = 65536) -> dict | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or metadata.st_nlink != 1
    ):
        raise NetworkReconcileError(f"Unsafe root-owned network state: {path}")
    if metadata.st_size > max_bytes:
        raise NetworkReconcileError(f"Network state is too large: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkReconcileError(f"Could not read network state {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise NetworkReconcileError(f"Network state must be an object: {path}")
    return payload


def _read_status() -> dict:
    try:
        payload = _safe_root_json(PRIVATE_STATUS_PATH)
    except NetworkReconcileError:
        return {}
    return payload or {}


def _write_status(status: str, **fields) -> dict:
    payload = {"status": status, "updated_at": _iso(), **fields}
    _atomic_json(PRIVATE_STATUS_PATH, payload, 0o600)

    # Publish only non-secret operational health to the daemon-readable runtime
    # directory. Keep the transaction/cooldown state private under
    # /var/lib/lattice-root.
    public = {
        key: payload.get(key)
        for key in (
            "status", "updated_at", "expected", "actual", "interface",
            "connection", "previous_actual", "retry_after_seconds", "error",
        )
        if payload.get(key) is not None
    }
    try:
        import grp
        lattice_gid = grp.getgrnam("lattice").gr_gid
    except KeyError as exc:
        raise NetworkReconcileError("The lattice service group is unavailable") from exc
    _atomic_json(HEALTH_STATUS_PATH, public, 0o640, gid=lattice_gid)
    return payload

def _role() -> str:
    try:
        role = ROLE_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise NetworkReconcileError(f"Could not read Lattice role: {exc}") from exc
    if role not in {"master", "worker"}:
        raise NetworkReconcileError("Lattice role is not configured")
    return role


def _default_route(runner=_run) -> dict:
    result = _checked(["ip", "-4", "route", "show", "default"], runner)
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        if "via" not in parts or "dev" not in parts:
            continue
        return {
            "gateway": parts[parts.index("via") + 1],
            "interface": parts[parts.index("dev") + 1],
        }
    raise NetworkReconcileError("No usable IPv4 default route is active")

def _interface_ipv4(interface: str, runner=_run) -> tuple[str, int]:
    result = _checked(
        ["ip", "-4", "-o", "address", "show", "dev", interface],
        runner,
    )
    for token in result.stdout.split():
        if "/" not in token or not token[0].isdigit():
            continue
        address, prefix = token.split("/", 1)
        try:
            return str(ipaddress.IPv4Address(address)), int(prefix)
        except (ipaddress.AddressValueError, ValueError):
            continue
    raise NetworkReconcileError(f"No IPv4 address is active on {interface}")


def _connection_name(interface: str, runner=_run) -> str:
    result = _checked(
        ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", interface],
        runner,
    )
    name = result.stdout.strip()
    if not name or name == "--":
        raise NetworkReconcileError(f"No NetworkManager connection is active on {interface}")
    return name

def _connection_values(connection: str, runner=_run) -> dict:
    fields = "connection.uuid,connection.type,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns"
    result = _checked(["nmcli", "-g", fields, "connection", "show", connection], runner)
    values = result.stdout.splitlines()
    while len(values) < 6:
        values.append("")
    return {
        "uuid": values[0].strip(),
        "type": values[1].strip(),
        "method": values[2].strip(),
        "addresses": values[3].strip(),
        "gateway": values[4].strip(),
        "dns": tuple(item for item in values[5].replace(";", ",").split(",") if item),
    }


def _gateway_mac(interface: str, gateway: str, runner=_run) -> str:
    runner(
        ["ping", "-c", "1", "-W", "2", "-I", interface, gateway],
        capture_output=True,
        text=True,
        timeout=8,
    )
    result = _checked(["ip", "neigh", "show", gateway, "dev", interface], runner)
    parts = result.stdout.lower().split()
    if "lladdr" not in parts:
        raise NetworkReconcileError("Could not fingerprint the trusted gateway")
    mac = parts[parts.index("lladdr") + 1]
    if not _MAC_RE.fullmatch(mac):
        raise NetworkReconcileError("Gateway MAC address is invalid")
    return mac

def _manual_profile_anchor(target: str, runner=_run) -> dict | None:
    listing = _checked(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], runner)
    anchors = []
    for line in listing.stdout.splitlines():
        if ":" not in line:
            continue
        name, kind = line.rsplit(":", 1)
        if kind not in {"802-11-wireless", "802-3-ethernet"}:
            continue
        values = _connection_values(name, runner)
        if values["method"] != "manual":
            continue
        for raw in values["addresses"].replace(";", ",").split(","):
            try:
                iface = ipaddress.IPv4Interface(raw.strip())
            except ValueError:
                continue
            if str(iface.ip) == target and values["gateway"]:
                anchors.append({"prefix": iface.network.prefixlen, "gateway": values["gateway"],
                                "dns": list(values["dns"]), "connection": name})
    if not anchors:
        return None
    signatures = {(a["prefix"], a["gateway"], tuple(a["dns"])) for a in anchors}
    if len(signatures) != 1:
        raise NetworkReconcileError("Static profiles disagree about the Lattice address policy")
    return anchors[0]


def _target_from_root_state(role: str, runner=_run) -> str:
    expected = read_expected_network()
    if expected and expected.get("address"):
        return str(ipaddress.IPv4Address(expected["address"]))

    if role == "master":
        candidate = str(load_config().master.ip)
        address = ipaddress.IPv4Address(candidate)
        if address.is_loopback or not address.is_private:
            raise NetworkReconcileError("Master static address is not configured safely")
        return str(address)

    result = _safe_root_json(WORKER_ASSIGNMENT_RESULT)
    if result and result.get("status") == "complete" and result.get("address"):
        return str(ipaddress.IPv4Address(result["address"]))

    # Legacy installs may have consumed/removed the one-time assignment result.
    # NetworkManager profiles are root-owned system state, so a unique manual
    # private IPv4 address is a safe migration source. Never guess if profiles
    # disagree.
    listing = _checked(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], runner)
    candidates = set()
    for line in listing.stdout.splitlines():
        if ":" not in line:
            continue
        name, kind = line.rsplit(":", 1)
        if kind not in {"802-11-wireless", "802-3-ethernet"}:
            continue
        values = _connection_values(name, runner)
        if values["method"] != "manual" or not values["addresses"]:
            continue
        for raw in values["addresses"].replace(";", ",").split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                candidate = ipaddress.IPv4Interface(raw).ip
            except ValueError:
                continue
            if candidate.is_private and not candidate.is_loopback:
                candidates.add(str(candidate))
    if len(candidates) == 1:
        return candidates.pop()
    raise NetworkReconcileError("Worker static address cannot be recovered unambiguously")


def _validate_policy(payload: dict) -> dict:
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise NetworkReconcileError("Unsupported network policy schema")
    try:
        address = ipaddress.IPv4Address(payload["address"])
        prefix = int(payload["prefix"])
        gateway = ipaddress.IPv4Address(payload["gateway"])
        network = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    except (KeyError, ValueError, ipaddress.AddressValueError) as exc:
        raise NetworkReconcileError("Saved network policy is invalid") from exc
    if gateway not in network or address in {network.network_address, network.broadcast_address}:
        raise NetworkReconcileError("Saved network policy network is invalid")
    mac = str(payload.get("gateway_mac", "")).lower()
    if not _MAC_RE.fullmatch(mac):
        raise NetworkReconcileError("Saved network policy gateway fingerprint is invalid")
    role = payload.get("role")
    if role not in {"master", "worker"}:
        raise NetworkReconcileError("Saved network policy role is invalid")
    return {
        "schema_version": _SCHEMA_VERSION,
        "role": role,
        "node_id": str(payload.get("node_id") or ""),
        "address": str(address),
        "prefix": prefix,
        "network": str(network),
        "gateway": str(gateway),
        "gateway_mac": mac,
        "dns": [str(item) for item in payload.get("dns", [])],
    }


def _load_policy() -> dict | None:
    payload = _safe_root_json(POLICY_PATH)
    return _validate_policy(payload) if payload else None

def _migrate_policy(runner=_run) -> dict:
    role = _role()
    target = _target_from_root_state(role, runner)
    route = _default_route(runner)
    actual, active_prefix = _interface_ipv4(route["interface"], runner)
    expected = read_expected_network()
    if expected:
        # The root-owned expected-network record is authoritative. Saved Wi-Fi
        # profiles may legitimately differ because the operator can switch
        # between multiple trusted SSIDs; do not treat inactive profile history
        # as a contradiction when exact root-owned policy already exists.
        prefix = int(expected["prefix"])
        gateway = str(ipaddress.IPv4Address(expected["gateway"]))
        dns = list(expected.get("dns", []))
    else:
        anchor = _manual_profile_anchor(target, runner)
        if not anchor:
            raise NetworkReconcileError("No root-owned static profile anchors the intended Lattice address")
        prefix = int(anchor["prefix"])
        gateway = str(ipaddress.IPv4Address(anchor["gateway"]))
        dns = list(anchor["dns"])
    network = ipaddress.IPv4Network(f"{target}/{prefix}", strict=False)
    active_network = ipaddress.IPv4Network(f"{actual}/{active_prefix}", strict=False)
    if active_network != network or str(ipaddress.IPv4Address(route["gateway"])) != gateway:
        raise NetworkReconcileError("Active network does not match the saved static Lattice policy")
    mac = _gateway_mac(route["interface"], gateway, runner)
    connection = _connection_name(route["interface"], runner)
    values = _connection_values(connection, runner)
    identity = load_node_identity()
    policy = _validate_policy({
        "schema_version": _SCHEMA_VERSION,
        "role": role,
        "node_id": identity.node_id if identity else "",
        "address": target,
        "prefix": prefix,
        "gateway": gateway,
        "gateway_mac": mac,
        "dns": list(dns or values["dns"] or (gateway,)),
    })
    _atomic_json(POLICY_PATH, policy, 0o600)
    write_expected_network({
        "interface": route["interface"], "connection": connection,
        "address": target, "prefix": prefix, "gateway": gateway,
        "dns": policy["dns"],
    })
    return policy

def _target_owners(target: str, runner=_run) -> list[str]:
    result = _checked(["ip", "-4", "-o", "address", "show"], runner)
    owners = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        interface = parts[1].rstrip(":")
        for token in parts:
            if not token.startswith(target + "/"):
                continue
            try:
                ipaddress.IPv4Interface(token)
            except ValueError:
                continue
            if interface not in owners:
                owners.append(interface)
    return owners


def _healthy_existing_owner(policy: dict, interface: str, runner=_run) -> dict:
    mac = _gateway_mac(interface, policy["gateway"], runner)
    if mac != policy["gateway_mac"]:
        raise NetworkReconcileError("Existing Lattice address is on an untrusted gateway")
    connection = _connection_name(interface, runner)
    return {"interface": interface, "connection": connection, "actual": policy["address"]}


def _trusted_active_path(policy: dict, runner=_run) -> dict:
    route = _default_route(runner)
    actual, prefix = _interface_ipv4(route["interface"], runner)
    network = ipaddress.IPv4Network(f"{actual}/{prefix}", strict=False)
    if str(network) != policy["network"]:
        raise NetworkReconcileError("Active network does not match the trusted Lattice LAN")
    if str(ipaddress.IPv4Address(route["gateway"])) != policy["gateway"]:
        raise NetworkReconcileError("Active gateway does not match the trusted Lattice LAN")
    mac = _gateway_mac(route["interface"], route["gateway"], runner)
    if mac != policy["gateway_mac"]:
        raise NetworkReconcileError("Active gateway fingerprint does not match the trusted Lattice LAN")
    connection = _connection_name(route["interface"], runner)
    values = _connection_values(connection, runner)
    return {
        "interface": route["interface"],
        "connection": connection,
        "connection_uuid": values["uuid"],
        "connection_type": values["type"],
        "actual": actual,
        "prefix": prefix,
    }


def _seconds_since(value: str | None, now: datetime) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (now - parsed).total_seconds())

def _rollback_committed_change(runner=_run) -> None:
    state = read_state()
    if not state or state.get("status") != "committed":
        raise NetworkReconcileError("No committed network snapshot is available for rollback")
    snapshot = state.get("snapshot")
    interface = state.get("interface")
    if not snapshot or not interface:
        raise NetworkReconcileError("Committed network snapshot is incomplete")
    restore_connection(snapshot, interface, runner)
    previous_expected = state.get("previous_expected")
    if previous_expected is None:
        clear_expected_network()
    else:
        write_expected_network(previous_expected)
    state["status"] = "reverted_after_postcheck"
    write_state(state)


def _role_service(role: str) -> str:
    return "lattice-master.service" if role == "master" else "lattice-worker.service"


def _service_active(role: str, runner=_run) -> bool:
    result = runner(
        ["systemctl", "is-active", "--quiet", _role_service(role)],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0

def reconcile_once(*, runner=_run, now: datetime | None = None) -> dict:
    if os.geteuid() != 0:
        raise NetworkReconcileError("Network reconciliation must run as root")
    now = now or _now()
    role = _role()
    policy = _load_policy()
    if role == "worker" and policy is None:
        assignment = _safe_root_json(WORKER_ASSIGNMENT_RESULT)
        if not (
            assignment
            and assignment.get("status") == "complete"
            and assignment.get("address")
        ):
            return _write_status("awaiting_assignment")
    policy = policy or _migrate_policy(runner)
    if policy["role"] != role:
        raise NetworkReconcileError("Network policy role does not match this machine")

    owners = _target_owners(policy["address"], runner)
    if len(owners) > 1:
        return _write_status(
            "repair_failed", expected=policy["address"], actual=policy["address"],
            error="The permanent Lattice address is active on multiple local interfaces",
        )
    if owners:
        owner = owners[0]
        try:
            active = _healthy_existing_owner(policy, owner, runner)
        except NetworkReconcileError as exc:
            return _write_status("unsafe_network", expected=policy["address"], error=str(exc))
        return _write_status(
            "healthy", expected=policy["address"], actual=policy["address"],
            interface=active["interface"], connection=active["connection"],
        )

    try:
        active = _trusted_active_path(policy, runner)
    except NetworkReconcileError as exc:
        return _write_status(
            "unsafe_network", expected=policy["address"], error=str(exc),
        )

    if active["actual"] == policy["address"]:
        return _write_status(
            "healthy", expected=policy["address"], actual=active["actual"],
            interface=active["interface"], connection=active["connection"],
        )

    previous = _read_status()
    same_drift = (
        previous.get("expected") == policy["address"]
        and previous.get("actual") == active["actual"]
        and previous.get("interface") == active["interface"]
        and previous.get("status") in {"drift_pending", "repair_cooldown", "repair_failed"}
    )
    first_seen = previous.get("first_seen") if same_drift else _iso(now)
    drift_age = _seconds_since(first_seen, now) or 0.0
    if drift_age < DRIFT_GRACE_SECONDS:
        return _write_status(
            "drift_pending", expected=policy["address"], actual=active["actual"],
            interface=active["interface"], connection=active["connection"],
            first_seen=first_seen, last_repair_at=previous.get("last_repair_at"),
            last_attempt_at=previous.get("last_attempt_at"),
            retry_after_seconds=max(1, int(DRIFT_GRACE_SECONDS - drift_age)),
        )

    last_attempt = previous.get("last_attempt_at") or previous.get("last_repair_at")
    last_repair_age = _seconds_since(last_attempt, now)
    if last_repair_age is not None and last_repair_age < REPAIR_COOLDOWN_SECONDS:
        return _write_status(
            "repair_cooldown", expected=policy["address"], actual=active["actual"],
            interface=active["interface"], connection=active["connection"],
            first_seen=first_seen, last_repair_at=previous.get("last_repair_at"),
            last_attempt_at=last_attempt,
        )

    try:
        if not is_address_available(active["interface"], policy["address"], runner):
            raise NetworkReconcileError("Expected Lattice address is already in use by another device")
        was_active = _service_active(policy["role"], runner)
        plan = StaticIPPlan(
            interface=active["interface"], connection=active["connection"],
            address=policy["address"], prefix=policy["prefix"],
            gateway=policy["gateway"], dns=tuple(policy["dns"]),
        )
        apply_static_ip(plan, runner=runner)
        if was_active and not _service_active(policy["role"], runner):
            _rollback_committed_change(runner)
            raise NetworkReconcileError("Lattice service did not remain healthy after network repair")
        verified = _trusted_active_path(policy, runner)
        if verified["actual"] != policy["address"]:
            _rollback_committed_change(runner)
            raise NetworkReconcileError("Expected address was not stable after repair")
    except (StaticIPError, NetworkReconcileError, OSError) as exc:
        return _write_status(
            "repair_failed", expected=policy["address"], actual=active["actual"],
            interface=active["interface"], connection=active["connection"],
            first_seen=first_seen, last_attempt_at=_iso(now), error=str(exc),
        )

    return _write_status(
        "repaired", expected=policy["address"], actual=policy["address"],
        previous_actual=active["actual"], interface=active["interface"],
        connection=active["connection"], first_seen=first_seen,
        last_repair_at=_iso(now), last_attempt_at=_iso(now),
    )


def main() -> None:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        try:
            result = reconcile_once()
        except Exception as exc:
            logger.exception("Automatic network reconciliation failed safely")
            result = _write_status("repair_failed", error=str(exc))


if __name__ == "__main__":
    main()

def read_network_health() -> dict | None:
    """Return safe read-only health for heartbeat/UI consumers."""
    try:
        payload = _safe_root_json(HEALTH_STATUS_PATH)
    except NetworkReconcileError as exc:
        return {"name": "network", "status": "unhealthy", "error": str(exc)}
    if not payload:
        return None
    state = str(payload.get("status") or "")
    updated_age = _seconds_since(payload.get("updated_at"), _now())
    stale = updated_age is None or updated_age > NETWORK_HEALTH_STALE_SECONDS or updated_age < -60
    healthy = state in {"healthy", "repaired"} and not stale
    return {
        "name": "network",
        "status": "healthy" if healthy else "unhealthy",
        "state": state,
        "expected": payload.get("expected"),
        "actual": payload.get("actual"),
        "error": payload.get("error"),
        "interface": payload.get("interface"),
        "stale": stale,
    }
