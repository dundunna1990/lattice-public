"""Signed fleet membership manifests.

The master signs each monotonically increasing fleet generation. Peers may
cache and redistribute the signed public manifest, but cannot forge changes.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from lattice.file_access.keys import (
    FileKeyError,
    fingerprint_ed25519_public_key,
    validate_ed25519_public_key,
)


MANIFEST_SCHEMA_VERSION = 1
SIGNING_NAMESPACE = "lattice-fleet"
SIGNING_IDENTITY = "lattice-fleet-master"

_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
)
_USER_RE = re.compile(
    r"^[a-z_][a-z0-9_-]{0,31}$"
)


class FleetManifestError(RuntimeError):
    """Raised when a fleet manifest is invalid or fails verification."""


def _valid_uuid(value: object, field: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise FleetManifestError(f"{field} is not a valid UUID") from exc
    return str(parsed)


def normalize_manifest(payload: object) -> dict:
    """Validate and canonicalize public fleet membership data."""
    if not isinstance(payload, dict):
        raise FleetManifestError("Fleet manifest must be an object")

    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise FleetManifestError("Unsupported fleet manifest schema")

    fleet_id = _valid_uuid(payload.get("fleet_id"), "fleet_id")

    generation = payload.get("generation")
    if not isinstance(generation, int) or generation < 0:
        raise FleetManifestError("Fleet generation must be a non-negative integer")

    raw_members = payload.get("members")
    if not isinstance(raw_members, list):
        raise FleetManifestError("Fleet members must be a list")

    members = []
    seen_node_ids: set[str] = set()
    seen_hostnames: set[str] = set()
    seen_file_keys: set[str] = set()
    seen_host_keys: set[str] = set()
    seen_shell_keys: set[str] = set()
    seen_shell_host_keys: set[str] = set()
    seen_ssh_identities: set[str] = set()

    for raw in raw_members:
        if not isinstance(raw, dict):
            raise FleetManifestError("Fleet member must be an object")

        node_id = _valid_uuid(raw.get("node_id"), "member node_id")

        if node_id in seen_node_ids:
            raise FleetManifestError("Fleet manifest contains a duplicate node")

        seen_node_ids.add(node_id)

        hostname = raw.get("hostname")
        role = raw.get("role")
        main_user = raw.get("main_user")

        if (
            not isinstance(hostname, str)
            or not _HOSTNAME_RE.fullmatch(hostname)
        ):
            raise FleetManifestError(
                "Fleet member hostname is invalid"
            )

        hostname_identity = hostname.casefold()

        if hostname_identity in seen_hostnames:
            raise FleetManifestError(
                "Fleet manifest contains a duplicate hostname"
            )

        seen_hostnames.add(hostname_identity)

        if role not in {"master", "worker"}:
            raise FleetManifestError(
                "Fleet member role is invalid"
            )

        if (
            not isinstance(main_user, str)
            or not _USER_RE.fullmatch(main_user)
        ):
            raise FleetManifestError(
                "Fleet member main user is invalid"
            )

        try:
            file_public_key = validate_ed25519_public_key(
                raw["file_public_key"]
            )
            file_host_public_key = validate_ed25519_public_key(
                raw["file_host_public_key"]
            )
        except (KeyError, FileKeyError) as exc:
            raise FleetManifestError(
                "Fleet member file identity is invalid"
            ) from exc

        file_key_identity = " ".join(
            file_public_key.split()[:2]
        )
        host_key_identity = " ".join(
            file_host_public_key.split()[:2]
        )

        if file_key_identity in seen_file_keys:
            raise FleetManifestError(
                "Fleet manifest reuses a file client key"
            )

        if host_key_identity in seen_host_keys:
            raise FleetManifestError(
                "Fleet manifest reuses a file host key"
            )

        if file_key_identity == host_key_identity:
            raise FleetManifestError(
                "File client and host SSH identities must be separate"
            )
        if file_key_identity in seen_ssh_identities or host_key_identity in seen_ssh_identities:
            raise FleetManifestError(
                "Fleet manifest reuses an SSH identity across channels or roles"
            )

        seen_file_keys.add(file_key_identity)
        seen_host_keys.add(host_key_identity)
        seen_ssh_identities.update((file_key_identity, host_key_identity))

        fingerprint = raw.get("file_host_key_fingerprint")
        if (
            not isinstance(fingerprint, str)
            or not fingerprint.startswith("SHA256:")
        ):
            raise FleetManifestError(
                "Fleet member file host fingerprint is invalid"
            )

        if fingerprint != fingerprint_ed25519_public_key(
            file_host_public_key
        ):
            raise FleetManifestError(
                "Fleet member host fingerprint does not match its host key"
            )

        key_generation = raw.get("file_key_generation")
        if not isinstance(key_generation, int) or key_generation < 1:
            raise FleetManifestError(
                "Fleet member file key generation is invalid"
            )

        file_next_values = (
            raw.get("file_next_public_key"),
            raw.get("file_next_host_public_key"),
            raw.get("file_next_host_key_fingerprint"),
            raw.get("file_next_key_generation"),
        )
        file_next_present = any(value is not None for value in file_next_values)
        file_next = None
        if file_next_present:
            if any(value is None for value in file_next_values):
                raise FleetManifestError("Fleet member next file identity is incomplete")
            try:
                next_file_public = validate_ed25519_public_key(file_next_values[0])
                next_file_host = validate_ed25519_public_key(file_next_values[1])
            except (TypeError, FileKeyError) as exc:
                raise FleetManifestError("Fleet member next file identity is invalid") from exc
            next_file_fingerprint = file_next_values[2]
            next_file_generation = file_next_values[3]
            if next_file_fingerprint != fingerprint_ed25519_public_key(next_file_host):
                raise FleetManifestError("Fleet member next file host fingerprint does not match its host key")
            if (isinstance(next_file_generation, bool) or not isinstance(next_file_generation, int)
                    or next_file_generation != key_generation + 1):
                raise FleetManifestError("Fleet member next file key generation is invalid")
            next_file_identity = " ".join(next_file_public.split()[:2])
            next_file_host_identity = " ".join(next_file_host.split()[:2])
            if next_file_identity == next_file_host_identity:
                raise FleetManifestError("Next file client and host SSH identities must be separate")
            if next_file_identity in seen_ssh_identities or next_file_host_identity in seen_ssh_identities:
                raise FleetManifestError("Next file SSH identities must be separate from every existing SSH identity")
            seen_file_keys.add(next_file_identity)
            seen_host_keys.add(next_file_host_identity)
            seen_ssh_identities.update((next_file_identity, next_file_host_identity))
            file_next = {
                "file_next_public_key": next_file_public,
                "file_next_host_public_key": next_file_host,
                "file_next_host_key_fingerprint": next_file_fingerprint,
                "file_next_key_generation": next_file_generation,
            }

        shell_public_key = raw.get("shell_public_key")
        shell_host_public_key = raw.get("shell_host_public_key")
        shell_fingerprint = raw.get("shell_host_key_fingerprint")
        shell_generation = raw.get("shell_key_generation", 0)
        shell_present = any(value is not None for value in (
            shell_public_key, shell_host_public_key, shell_fingerprint
        ))
        if shell_present:
            try:
                shell_public_key = validate_ed25519_public_key(shell_public_key)
                shell_host_public_key = validate_ed25519_public_key(shell_host_public_key)
            except (TypeError, FileKeyError) as exc:
                raise FleetManifestError("Fleet member shell identity is invalid") from exc
            if shell_fingerprint != fingerprint_ed25519_public_key(shell_host_public_key):
                raise FleetManifestError("Fleet member shell host fingerprint does not match its host key")
            if not isinstance(shell_generation, int) or shell_generation < 1:
                raise FleetManifestError("Fleet member shell key generation is invalid")
            shell_key_identity = " ".join(shell_public_key.split()[:2])
            shell_host_identity = " ".join(shell_host_public_key.split()[:2])
            if shell_key_identity in seen_shell_keys or shell_host_identity in seen_shell_host_keys:
                raise FleetManifestError("Fleet manifest reuses a shell SSH key")
            if shell_key_identity == shell_host_identity:
                raise FleetManifestError("Shell client and host SSH identities must be separate")
            if shell_key_identity in seen_ssh_identities or shell_host_identity in seen_ssh_identities:
                raise FleetManifestError("Shell SSH identities must be separate from every existing SSH identity")
            seen_shell_keys.add(shell_key_identity)
            seen_shell_host_keys.add(shell_host_identity)
            seen_ssh_identities.update((shell_key_identity, shell_host_identity))

        member = {
                "node_id": node_id,
                "hostname": hostname.strip(),
                "role": role,
                "main_user": main_user.strip(),
                "file_public_key": file_public_key,
                "file_host_public_key": file_host_public_key,
                "file_host_key_fingerprint": fingerprint,
                "file_key_generation": key_generation,
            }
        if file_next is not None:
            member.update(file_next)
        if shell_present:
            member.update({
                "shell_public_key": shell_public_key,
                "shell_host_public_key": shell_host_public_key,
                "shell_host_key_fingerprint": shell_fingerprint,
                "shell_key_generation": shell_generation,
            })

            next_values = (
                raw.get("shell_next_public_key"),
                raw.get("shell_next_host_public_key"),
                raw.get("shell_next_host_key_fingerprint"),
                raw.get("shell_next_key_generation"),
            )
            next_present = any(value is not None for value in next_values)
            if next_present:
                if any(value is None for value in next_values):
                    raise FleetManifestError("Fleet member next shell identity is incomplete")
                try:
                    next_public = validate_ed25519_public_key(next_values[0])
                    next_host = validate_ed25519_public_key(next_values[1])
                except (TypeError, FileKeyError) as exc:
                    raise FleetManifestError("Fleet member next shell identity is invalid") from exc
                next_fingerprint = next_values[2]
                next_generation = next_values[3]
                if next_fingerprint != fingerprint_ed25519_public_key(next_host):
                    raise FleetManifestError("Fleet member next shell host fingerprint does not match its host key")
                if (
                    isinstance(next_generation, bool)
                    or not isinstance(next_generation, int)
                    or next_generation != shell_generation + 1
                ):
                    raise FleetManifestError("Fleet member next shell key generation is invalid")
                next_client_identity = " ".join(next_public.split()[:2])
                next_host_identity = " ".join(next_host.split()[:2])
                if next_client_identity in seen_shell_keys or next_host_identity in seen_shell_host_keys:
                    raise FleetManifestError("Fleet manifest reuses a shell SSH key")
                if next_client_identity == next_host_identity:
                    raise FleetManifestError("Next shell client and host SSH identities must be separate")
                if next_client_identity in seen_ssh_identities or next_host_identity in seen_ssh_identities:
                    raise FleetManifestError("Next shell SSH identities must be separate from every existing SSH identity")
                seen_shell_keys.add(next_client_identity)
                seen_shell_host_keys.add(next_host_identity)
                seen_ssh_identities.update((next_client_identity, next_host_identity))
                member.update({
                    "shell_next_public_key": next_public,
                    "shell_next_host_public_key": next_host,
                    "shell_next_host_key_fingerprint": next_fingerprint,
                    "shell_next_key_generation": next_generation,
                })
        members.append(member)

    members.sort(key=lambda item: item["node_id"])

    raw_revoked = payload.get("revoked", [])
    if not isinstance(raw_revoked, list):
        raise FleetManifestError("Revoked members must be a list")

    revoked = sorted(
        {
            _valid_uuid(node_id, "revoked node_id")
            for node_id in raw_revoked
        }
    )

    if seen_node_ids.intersection(revoked):
        raise FleetManifestError(
            "A node cannot be active and revoked in the same generation"
        )

    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "fleet_id": fleet_id,
        "generation": generation,
        "members": members,
        "revoked": revoked,
    }


def canonical_manifest_bytes(payload: object) -> bytes:
    """Return deterministic bytes for signing and comparison."""
    normalized = normalize_manifest(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_manifest(
    payload: object,
    signing_private_key: Path,
) -> str:
    """Sign one normalized manifest using the master's Ed25519 identity."""
    message = canonical_manifest_bytes(payload)

    with tempfile.TemporaryDirectory(prefix="lattice-manifest-sign-") as tmp:
        message_path = Path(tmp) / "manifest.json"
        message_path.write_bytes(message)

        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-q",
                    "-f",
                    str(signing_private_key),
                    "-n",
                    SIGNING_NAMESPACE,
                    str(message_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FleetManifestError(
                f"Could not sign fleet manifest: {exc}"
            ) from exc

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise FleetManifestError(
                f"Could not sign fleet manifest: {detail}"
            )

        signature_path = Path(str(message_path) + ".sig")

        try:
            signature = signature_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise FleetManifestError(
                f"Could not read fleet signature: {exc}"
            ) from exc

    if "BEGIN SSH SIGNATURE" not in signature:
        raise FleetManifestError("Generated fleet signature is invalid")

    return signature


def verify_manifest(
    payload: object,
    signature: str,
    signing_public_key: str,
) -> bool:
    """Verify a manifest using the master's pinned signing public key."""
    try:
        public_key = validate_ed25519_public_key(signing_public_key)
    except FileKeyError as exc:
        raise FleetManifestError(
            "Fleet signing public key is invalid"
        ) from exc

    if (
        not isinstance(signature, str)
        or "BEGIN SSH SIGNATURE" not in signature
    ):
        raise FleetManifestError("Fleet signature has an invalid format")

    message = canonical_manifest_bytes(payload)

    with tempfile.TemporaryDirectory(prefix="lattice-manifest-verify-") as tmp:
        tmp_path = Path(tmp)

        allowed_signers = tmp_path / "allowed_signers"
        signature_path = tmp_path / "manifest.sig"

        allowed_signers.write_text(
            f"{SIGNING_IDENTITY} {public_key}\n",
            encoding="utf-8",
        )
        signature_path.write_text(signature, encoding="utf-8")

        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-q",
                    "-f",
                    str(allowed_signers),
                    "-I",
                    SIGNING_IDENTITY,
                    "-n",
                    SIGNING_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=message,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FleetManifestError(
                f"Could not verify fleet manifest: {exc}"
            ) from exc

    return result.returncode == 0


def require_newer_generation(
    current_generation: int,
    candidate_payload: object,
) -> dict:
    """Reject replay/rollback and return the normalized newer generation."""
    if not isinstance(current_generation, int) or current_generation < 0:
        raise FleetManifestError("Current fleet generation is invalid")

    normalized = normalize_manifest(candidate_payload)

    if normalized["generation"] <= current_generation:
        raise FleetManifestError(
            "Fleet manifest is not newer than the currently trusted generation"
        )

    return normalized
