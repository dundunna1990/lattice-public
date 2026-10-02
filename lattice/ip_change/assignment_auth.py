"""Cryptographic authorization for exact Master-issued Worker network assignments."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from lattice.file_access.keys import FileKeyError, validate_ed25519_public_key

SIGNING_NAMESPACE = "lattice-network-assignment-v1"
SIGNING_IDENTITY = "lattice-fleet-master"
DEFAULT_SIGNING_KEY = Path("/etc/lattice/fleet-signing/fleet_signing_ed25519")


def _default_signing_key() -> Path:
    directory = Path(__import__("os").environ.get(
        "LATTICE_FLEET_SIGNING_DIR", str(DEFAULT_SIGNING_KEY.parent)
    ))
    return directory / DEFAULT_SIGNING_KEY.name
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class NetworkAssignmentAuthError(RuntimeError):
    pass


def normalize_assignment(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise NetworkAssignmentAuthError("Network assignment must be an object")
    allowed = {
        "assignment_id", "worker_hostname", "worker_node_id", "issued_at",
        "address", "prefix", "gateway", "dns", "signature",
    }
    unexpected = set(payload) - allowed
    if unexpected:
        raise NetworkAssignmentAuthError("Network assignment contains unexpected fields")
    try:
        assignment_id = str(uuid.UUID(str(payload["assignment_id"])))
        if uuid.UUID(assignment_id).version != 4:
            raise ValueError("assignment id is not UUIDv4")
        worker_node_id = str(uuid.UUID(str(payload["worker_node_id"])))
        if uuid.UUID(worker_node_id).version != 4:
            raise ValueError("worker node id is not UUIDv4")
        worker_hostname = str(payload["worker_hostname"])
        issued_at = datetime.fromisoformat(str(payload["issued_at"]))
        if issued_at.tzinfo is None:
            raise ValueError("timestamp missing timezone")
        address = str(__import__("ipaddress").IPv4Address(payload["address"]))
        gateway = str(__import__("ipaddress").IPv4Address(payload["gateway"]))
        prefix = int(payload["prefix"])
        if not 1 <= prefix <= 30:
            raise ValueError("prefix outside range")
        dns = [str(__import__("ipaddress").IPv4Address(v)) for v in payload.get("dns", [])]
    except (KeyError, TypeError, ValueError) as exc:
        raise NetworkAssignmentAuthError("Network assignment contains invalid fields") from exc
    if not _HOSTNAME_RE.fullmatch(worker_hostname):
        raise NetworkAssignmentAuthError("Worker hostname is invalid")
    if len(dns) > 4:
        raise NetworkAssignmentAuthError("Too many DNS servers in network assignment")
    return {
        "assignment_id": assignment_id,
        "worker_hostname": worker_hostname,
        "worker_node_id": worker_node_id,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "address": address,
        "prefix": prefix,
        "gateway": gateway,
        "dns": dns,
    }


def canonical_assignment_bytes(payload: object) -> bytes:
    return json.dumps(
        normalize_assignment(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sign_network_assignment(payload: object, private_key: Path | None = None) -> dict:
    normalized = normalize_assignment(payload)
    private_key = _default_signing_key() if private_key is None else Path(private_key)
    if not private_key.is_file():
        raise NetworkAssignmentAuthError("Fleet signing private key is unavailable")
    with tempfile.TemporaryDirectory(prefix="lattice-network-sign-") as tmp:
        message = Path(tmp) / "assignment.json"
        message.write_bytes(canonical_assignment_bytes(normalized))
        try:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-q", "-f", str(private_key), "-n", SIGNING_NAMESPACE, str(message)],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NetworkAssignmentAuthError(f"Could not sign network assignment: {exc}") from exc
        if result.returncode != 0:
            raise NetworkAssignmentAuthError(
                "Could not sign network assignment: " + (result.stderr or result.stdout or "ssh-keygen failed").strip()
            )
        try:
            signature = Path(str(message) + ".sig").read_text(encoding="utf-8")
        except OSError as exc:
            raise NetworkAssignmentAuthError(f"Could not read network assignment signature: {exc}") from exc
    if "BEGIN SSH SIGNATURE" not in signature:
        raise NetworkAssignmentAuthError("Generated network assignment signature is invalid")
    return {**normalized, "signature": signature}


def verify_network_assignment(payload: object, signature: str, public_key: str) -> dict:
    normalized = normalize_assignment(payload)
    try:
        public_key = validate_ed25519_public_key(public_key)
    except FileKeyError as exc:
        raise NetworkAssignmentAuthError("Fleet signing public key is invalid") from exc
    if not isinstance(signature, str) or "BEGIN SSH SIGNATURE" not in signature:
        raise NetworkAssignmentAuthError("Network assignment signature is invalid")
    with tempfile.TemporaryDirectory(prefix="lattice-network-verify-") as tmp:
        tmp_path = Path(tmp)
        allowed = tmp_path / "allowed_signers"
        sig = tmp_path / "assignment.sig"
        allowed.write_text(f"{SIGNING_IDENTITY} {public_key}\n", encoding="utf-8")
        sig.write_text(signature, encoding="utf-8")
        try:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-q", "-f", str(allowed), "-I", SIGNING_IDENTITY,
                 "-n", SIGNING_NAMESPACE, "-s", str(sig)],
                input=canonical_assignment_bytes(normalized), capture_output=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NetworkAssignmentAuthError(f"Could not verify network assignment: {exc}") from exc
    if result.returncode != 0:
        raise NetworkAssignmentAuthError("Network assignment signature did not verify")
    return normalized
