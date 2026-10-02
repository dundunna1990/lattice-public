"""Signed source-to-target authorization for remote backup repositories."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import uuid

from lattice.file_access.keys import (
    FileKeyError, fingerprint_ed25519_public_key, validate_ed25519_public_key,
)

SCHEMA_VERSION = 1
SIGNING_NAMESPACE = "lattice-backup-assignment"
SIGNING_IDENTITY = "lattice-fleet-master"


class BackupAssignmentError(RuntimeError):
    pass


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupAssignmentError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupAssignmentError(f"{label} must be UUIDv4")
    return str(parsed)


def normalize_assignment(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise BackupAssignmentError("Backup assignment document has an invalid schema")
    fleet_id = _uuid4(payload.get("fleet_id"), "Fleet ID")
    generation = payload.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise BackupAssignmentError("Backup assignment generation must be positive")
    raw = payload.get("assignments")
    if not isinstance(raw, list) or len(raw) > 256:
        raise BackupAssignmentError("Backup assignments must be a bounded list")
    assignments: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise BackupAssignmentError("Backup assignment must be an object")
        source = _uuid4(item.get("source_node_id"), "Source Node ID")
        target = _uuid4(item.get("target_node_id"), "Target Node ID")
        target_uuid = _uuid4(item.get("target_uuid"), "Target ID")
        repository_id = _uuid4(item.get("repository_id"), "Repository ID")
        if source == target:
            raise BackupAssignmentError("Remote backup assignment must use different nodes")
        try:
            public_key = validate_ed25519_public_key(str(item.get("backup_public_key")))
            host_public_key = validate_ed25519_public_key(
                str(item.get("backup_host_public_key"))
            )
        except FileKeyError as exc:
            raise BackupAssignmentError("Backup transport public key is invalid") from exc
        host_fingerprint = item.get("backup_host_key_fingerprint")
        if host_fingerprint != fingerprint_ed25519_public_key(host_public_key):
            raise BackupAssignmentError("Backup host fingerprint does not match its host key")
        if public_key.split()[:2] == host_public_key.split()[:2]:
            raise BackupAssignmentError("Backup client and host keys must be separate")
        pair = (source, target_uuid)
        if pair in seen:
            raise BackupAssignmentError("Backup assignment is duplicated")
        seen.add(pair)
        assignments.append({
            "source_node_id": source,
            "target_node_id": target,
            "target_uuid": target_uuid,
            "repository_id": repository_id,
            "backup_public_key": public_key,
            "backup_host_public_key": host_public_key,
            "backup_host_key_fingerprint": host_fingerprint,
        })
    assignments.sort(key=lambda value: (value["target_node_id"], value["source_node_id"], value["target_uuid"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "fleet_id": fleet_id,
        "generation": generation,
        "assignments": assignments,
    }


def canonical_assignment_bytes(payload: object) -> bytes:
    return json.dumps(
        normalize_assignment(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_assignment(payload: object, signing_private_key: Path) -> str:
    message = canonical_assignment_bytes(payload)
    with tempfile.TemporaryDirectory(prefix="lattice-backup-sign-") as tmp:
        message_path = Path(tmp) / "assignment.json"
        message_path.write_bytes(message)
        try:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-q", "-f", str(signing_private_key),
                 "-n", SIGNING_NAMESPACE, str(message_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupAssignmentError(f"Could not sign backup assignment: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise BackupAssignmentError(f"Could not sign backup assignment: {detail}")
        signature = Path(str(message_path) + ".sig").read_text(encoding="utf-8")
    if "BEGIN SSH SIGNATURE" not in signature:
        raise BackupAssignmentError("Generated backup assignment signature is invalid")
    return signature


def verify_assignment(payload: object, signature: str, signing_public_key: str) -> bool:
    try:
        public_key = validate_ed25519_public_key(signing_public_key)
    except FileKeyError as exc:
        raise BackupAssignmentError("Fleet signing public key is invalid") from exc
    if not isinstance(signature, str) or "BEGIN SSH SIGNATURE" not in signature:
        raise BackupAssignmentError("Backup assignment signature has an invalid format")
    message = canonical_assignment_bytes(payload)
    with tempfile.TemporaryDirectory(prefix="lattice-backup-verify-") as tmp:
        root = Path(tmp)
        allowed = root / "allowed_signers"
        sig = root / "assignment.sig"
        allowed.write_text(f"{SIGNING_IDENTITY} {public_key}\n", encoding="utf-8")
        sig.write_text(signature, encoding="utf-8")
        try:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-q", "-f", str(allowed),
                 "-I", SIGNING_IDENTITY, "-n", SIGNING_NAMESPACE, "-s", str(sig)],
                input=message,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupAssignmentError(f"Could not verify backup assignment: {exc}") from exc
    return result.returncode == 0
