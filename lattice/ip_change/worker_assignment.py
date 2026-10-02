"""Root-only worker-side executor for its one pairing-time address assignment."""

import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import ipaddress
import hashlib
import socket
import uuid
from datetime import datetime, timezone
import stat
import pwd
import grp

import netifaces

from lattice.ip_change.setup import (
    StaticIPError,
    StaticIPPlan,
    apply_static_ip,
    detect_connection,
    validate_plan,
)
from lattice.onboarding import PairingError
from lattice.ip_change.assignment_auth import (
    NetworkAssignmentAuthError,
    normalize_assignment,
    verify_network_assignment,
)


REQUEST_PATH = Path("/var/lib/lattice/network-assignment-request.json")
RESULT_PATH = Path("/var/lib/lattice/network-assignment-result.json")
HELPER_PATH = Path("/opt/lattice/bin/lattice-network-exec")
NETWORK_POLICY_PATH = Path("/etc/lattice/network-policy.json")
NETWORK_RECONCILE_TIMER = "lattice-network-reconcile.timer"
FLEET_BOOTSTRAP_PATH = Path("/etc/lattice/fleet/bootstrap.json")
NODE_IDENTITY_PATH = Path("/var/lib/lattice/node-identity.json")
ASSIGNMENT_AUTHORITY_PATH = Path("/var/lib/lattice-root/network-assignment-authority.json")


def _result_path_for(request_path: Path) -> Path:
    """Keep non-production requests self-contained beside their request file."""
    request_path = Path(request_path)
    if request_path == REQUEST_PATH and request_path.parent == Path("/var/lib/lattice"):
        return RESULT_PATH
    return request_path.with_name("network-assignment-result.json")


def queue_network_assignment(payload):
    """Queue one Master-signed exact assignment for the root verifier."""
    try:
        normalize_assignment(payload)
    except NetworkAssignmentAuthError as exc:
        raise StaticIPError("The master sent an invalid static-IP assignment.") from exc
    signature = payload.get("signature") if isinstance(payload, dict) else None
    if not isinstance(signature, str) or "BEGIN SSH SIGNATURE" not in signature:
        raise StaticIPError("The master did not sign the static-IP assignment.")
    if REQUEST_PATH.exists():
        raise StaticIPError("A network assignment is already in progress on this worker.")
    _result_path_for(REQUEST_PATH).unlink(missing_ok=True)

    REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(dir=REQUEST_PATH.parent, prefix=f".{REQUEST_PATH.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, REQUEST_PATH)
        # The daemon only queues bytes. Root independently verifies the exact
        # Master signature and replay ledger before any network mutation.
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def _default_interface():
    try:
        return netifaces.gateways()["default"][netifaces.AF_INET][1]
    except (KeyError, IndexError, TypeError) as exc:
        raise StaticIPError("Could not find this worker's active IPv4 interface.") from exc


def _read_assignment_request(request_path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(request_path, flags)
    except OSError as exc:
        raise StaticIPError(f"Could not read the network assignment request: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StaticIPError("Network assignment request is not a single regular file")
        if metadata.st_mode & 0o077:
            raise StaticIPError("Network assignment request permissions are unsafe")
        if Path(request_path) == REQUEST_PATH:
            try:
                lattice_uid = pwd.getpwnam("lattice").pw_uid
            except KeyError as exc:
                raise StaticIPError("The lattice service account is unavailable") from exc
            if metadata.st_uid != lattice_uid:
                raise StaticIPError("Network assignment request owner is unsafe")
        if metadata.st_size > 4096:
            raise StaticIPError("Network assignment request is too large")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StaticIPError(f"Could not parse the network assignment request: {exc}") from exc
    if not isinstance(payload, dict):
        raise StaticIPError("Network assignment request has an invalid format")
    return payload


def _safe_root_json(path: Path, *, maximum: int = 32768) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StaticIPError(f"Could not safely read trusted file {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StaticIPError(f"Trusted file {path} is not a single regular file")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise StaticIPError(f"Trusted file {path} has unsafe ownership or permissions")
        if metadata.st_size > maximum:
            raise StaticIPError(f"Trusted file {path} is unexpectedly large")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StaticIPError(f"Trusted file {path} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise StaticIPError(f"Trusted file {path} has an invalid format")
    return payload


def _atomic_root_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.parent.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise StaticIPError(f"Trusted directory {path.parent} has unsafe ownership or permissions")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def _verify_and_consume_authorization(payload: dict, *, max_age_seconds: int = 120) -> dict:
    """Verify the exact Master signature and burn root-owned one-use authority."""
    bootstrap = _safe_root_json(FLEET_BOOTSTRAP_PATH)
    identity = _safe_root_json(NODE_IDENTITY_PATH)
    authority = _safe_root_json(ASSIGNMENT_AUTHORITY_PATH)

    if authority.get("version") != 1 or authority.get("state") != "ready":
        raise StaticIPError("The root-owned one-time network authorization is not available")

    worker_hostname = socket.gethostname()
    worker_node_id = str(identity.get("node_id", ""))
    if (
        authority.get("worker_hostname") != worker_hostname
        or authority.get("worker_node_id") != worker_node_id
    ):
        raise StaticIPError("The root-owned network authorization targets a different worker")
    if (
        authority.get("fleet_id") != bootstrap.get("fleet_id")
        or authority.get("master_node_id") != bootstrap.get("master_node_id")
    ):
        raise StaticIPError("The root-owned network authorization does not match the paired fleet")

    public_key = authority.get("fleet_signing_public_key")
    if public_key != bootstrap.get("fleet_signing_public_key"):
        raise StaticIPError("The root-owned network authorization has the wrong Master signing key")

    signature = payload.get("signature")
    try:
        normalized = verify_network_assignment(payload, signature, public_key)
    except NetworkAssignmentAuthError as exc:
        raise StaticIPError(
            f"Network assignment is not authorized by the paired Master: {exc}"
        ) from exc
    if normalized["worker_hostname"] != worker_hostname:
        raise StaticIPError("Signed network assignment targets a different worker hostname")
    if normalized["worker_node_id"] != worker_node_id:
        raise StaticIPError("Signed network assignment targets a different worker identity")

    try:
        issued = datetime.fromisoformat(normalized["issued_at"])
    except ValueError as exc:
        raise StaticIPError("Signed network assignment timestamp is invalid") from exc
    age = (datetime.now(timezone.utc) - issued).total_seconds()
    if age < -30 or age > max_age_seconds:
        raise StaticIPError("Signed network assignment has expired")

    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    consumed = dict(authority)
    consumed.update({
        "state": "consumed",
        "assignment_id": normalized["assignment_id"],
        "assignment_digest": digest,
        "consumed_at": datetime.now(timezone.utc).isoformat(),
    })
    # Burn the root-owned capability before any network mutation. A compromised
    # daemon cannot create, reset, or replay this authorization.
    _atomic_root_json(ASSIGNMENT_AUTHORITY_PATH, consumed)
    return normalized


def _arm_network_reconciliation(runner=subprocess.run) -> None:
    """Enable and positively re-arm self-healing after verified assignment."""
    try:
        enable_result = runner(
            ["systemctl", "enable", NETWORK_RECONCILE_TIMER],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if enable_result.returncode != 0:
            detail = (enable_result.stderr or enable_result.stdout or "systemd error").strip()
            raise StaticIPError(
                f"Could not enable permanent-address self-healing: {detail}"
            )
        result = runner(
            ["systemctl", "restart", NETWORK_RECONCILE_TIMER],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StaticIPError(f"Could not enable permanent-address self-healing: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemd error").strip()
        raise StaticIPError(
            f"Could not enable permanent-address self-healing: {detail}"
        )


def run_assignment(request_path=REQUEST_PATH):
    request_path = Path(request_path)
    payload = _read_assignment_request(request_path)
    if request_path == REQUEST_PATH:
        payload = {**payload, **_verify_and_consume_authorization(payload)}
    interface = _default_interface()
    plan = StaticIPPlan(
        interface=interface,
        connection=detect_connection(interface),
        address=payload["address"],
        prefix=int(payload["prefix"]),
        gateway=payload["gateway"],
        dns=tuple(payload.get("dns", ())),
    )
    validate_plan(plan)
    try:
        apply_static_ip(plan)
        # A fresh Worker must never preserve a policy learned from its temporary
        # pre-pairing address. The successful one-time Master assignment is the
        # first authority allowed to seed permanent-address reconciliation.
        if request_path == REQUEST_PATH:
            NETWORK_POLICY_PATH.unlink(missing_ok=True)
        _write_assignment_result(
            {"status": "complete", "address": plan.address},
            _result_path_for(request_path),
        )
        if request_path == REQUEST_PATH:
            _arm_network_reconciliation()
    except Exception as exc:
        _write_assignment_result(
            {"status": "failed", "address": payload.get("address"), "error": str(exc)[:300]},
            _result_path_for(request_path),
        )
        # Do not let a failed request continuously retrigger the path unit.
        # Preserve it for local diagnosis while blocking automatic retries.
        failed_path = request_path.with_suffix(".failed.json")
        request_path.replace(failed_path)
        raise
    request_path.unlink(missing_ok=True)
    return plan


def _write_assignment_result(payload: dict, result_path: Path = RESULT_PATH) -> None:
    """Atomically publish the root helper's exact result to the worker API."""
    result_path = Path(result_path)
    result_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(dir=result_path.parent, prefix=f".{result_path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            lattice_group = grp.getgrnam("lattice").gr_gid
            os.chown(temporary, 0, lattice_group)
        os.replace(temporary, result_path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def read_assignment_result() -> dict | None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(RESULT_PATH, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StaticIPError(f"Could not safely read the network-assignment result: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StaticIPError("The network-assignment result is not a single regular file")
        if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
            raise StaticIPError("The network-assignment result has unsafe ownership or permissions")
        if metadata.st_size > 4096:
            raise StaticIPError("The network-assignment result is too large")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StaticIPError("The network-assignment result is invalid") from exc
    if not isinstance(result, dict) or result.get("status") not in {"complete", "failed"}:
        raise StaticIPError("The network-assignment result is invalid")
    return result


def main():
    if os.geteuid() != 0:
        raise SystemExit("This helper must run as root.")
    if len(sys.argv) != 2 or Path(sys.argv[1]) != REQUEST_PATH:
        raise SystemExit("Only the canonical network-assignment request path is accepted.")
    try:
        run_assignment()
    except (StaticIPError, PairingError, KeyError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc


if __name__ == "__main__":
    main()
