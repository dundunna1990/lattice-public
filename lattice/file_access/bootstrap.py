"""Root of trust for Lattice full-fleet file membership."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import uuid

from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import (
    FileKeyError,
    ensure_fleet_signing_identity,
    fingerprint_ed25519_public_key,
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
    sign_manifest,
    verify_manifest,
)
from lattice.file_access.profile import ensure_local_file_profile


DEFAULT_FLEET_SIGNING_DIR = Path("/etc/lattice/fleet-signing")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class FleetBootstrapError(RuntimeError):
    """Raised when the permanent fleet root of trust is invalid."""


@dataclass(frozen=True)
class MasterFleetBootstrap:
    fleet_id: str
    generation: int
    node_id: str
    hostname: str
    main_user: str
    file_public_key: str
    file_host_public_key: str
    file_host_key_fingerprint: str
    shell_public_key: str
    shell_host_public_key: str
    shell_host_key_fingerprint: str
    fleet_signing_public_key: str
    manifest: dict
    signature: str


def _uuid4(value: object, field: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise FleetBootstrapError(f"{field} is invalid") from exc

    if parsed.version != 4:
        raise FleetBootstrapError(f"{field} must be UUIDv4")

    return str(parsed)


def _signing_dir() -> Path:
    override = os.environ.get("LATTICE_FLEET_SIGNING_DIR")
    return Path(override) if override else DEFAULT_FLEET_SIGNING_DIR


def resolve_local_main_user() -> str:
    """Resolve the human account without ever selecting root/lattice."""
    existing = load_node_identity()
    if existing is not None:
        return existing.main_user

    candidates: list[str] = []

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidates.append(sudo_user)

    if os.geteuid() != 0:
        try:
            candidates.append(pwd.getpwuid(os.geteuid()).pw_name)
        except KeyError:
            pass

    for candidate in candidates:
        if not candidate or candidate in {"root", "lattice"}:
            continue

        try:
            account = pwd.getpwnam(candidate)
        except KeyError:
            continue

        if account.pw_uid > 0:
            return account.pw_name

    raise FleetBootstrapError(
        "Could not determine the main human account. "
        "Run Lattice setup through sudo from that account."
    )


def validate_master_bootstrap(
    *,
    fleet_id: object,
    master_node_id: object,
    master_file_public_key: object,
    master_file_host_public_key: object,
    master_file_host_key_fingerprint: object,
    master_shell_public_key: object = None,
    master_shell_host_public_key: object = None,
    master_shell_host_key_fingerprint: object = None,
    fleet_signing_public_key: object = None,
) -> dict[str, str]:
    """Validate public master trust anchors before local approval."""
    try:
        file_key = validate_ed25519_public_key(
            str(master_file_public_key)
        )
        host_key = validate_ed25519_public_key(
            str(master_file_host_public_key)
        )
        signing_key = validate_ed25519_public_key(str(fleet_signing_public_key))
        shell_values = (master_shell_public_key, master_shell_host_public_key, master_shell_host_key_fingerprint)
        shell_present = any(value is not None for value in shell_values)
        shell_key = shell_host_key = None
        if shell_present:
            if any(value is None for value in shell_values):
                raise FileKeyError("Master shell identity is incomplete")
            shell_key = validate_ed25519_public_key(str(master_shell_public_key))
            shell_host_key = validate_ed25519_public_key(str(master_shell_host_public_key))
    except FileKeyError as exc:
        raise FleetBootstrapError(
            "Master file/fleet public identity is invalid"
        ) from exc

    fingerprint = str(master_file_host_key_fingerprint)

    if fingerprint != fingerprint_ed25519_public_key(host_key):
        raise FleetBootstrapError(
            "Master file host fingerprint does not match its host key"
        )

    shell_fingerprint = None
    if shell_present:
        shell_fingerprint = str(master_shell_host_key_fingerprint)
        if shell_fingerprint != fingerprint_ed25519_public_key(shell_host_key):
            raise FleetBootstrapError("Master shell host fingerprint does not match its host key")
        if " ".join(shell_key.split()[:2]) == " ".join(file_key.split()[:2]):
            raise FleetBootstrapError("Master shell and file client keys must be separate")
        if " ".join(shell_host_key.split()[:2]) == " ".join(host_key.split()[:2]):
            raise FleetBootstrapError("Master shell and file host keys must be separate")

    result = {
        "fleet_id": _uuid4(fleet_id, "fleet ID"),
        "master_node_id": _uuid4(
            master_node_id,
            "master node ID",
        ),
        "master_file_public_key": file_key,
        "master_file_host_public_key": host_key,
        "master_file_host_key_fingerprint": fingerprint,
        "fleet_signing_public_key": signing_key,
    }
    if shell_present:
        result.update({
            "master_shell_public_key": shell_key,
            "master_shell_host_public_key": shell_host_key,
            "master_shell_host_key_fingerprint": shell_fingerprint,
        })
    return result


def _master_member(profile, hostname: str) -> dict:
    return {
        "node_id": profile.node_id,
        "hostname": hostname,
        "role": "master",
        "main_user": profile.main_user,
        "file_public_key": profile.client.public_key_text,
        "file_host_public_key": profile.host.public_key_text,
        "file_host_key_fingerprint": profile.host.fingerprint,
        "file_key_generation": 1,
        "shell_public_key": profile.shell_client.public_key_text,
        "shell_host_public_key": profile.shell_host.public_key_text,
        "shell_host_key_fingerprint": profile.shell_host.fingerprint,
        "shell_key_generation": 1,
    }


def _return_bootstrap(
    *,
    fleet_id: str,
    generation: int,
    hostname: str,
    profile,
    signing,
    manifest: dict,
    signature: str,
) -> MasterFleetBootstrap:
    return MasterFleetBootstrap(
        fleet_id=fleet_id,
        generation=generation,
        node_id=profile.node_id,
        hostname=hostname,
        main_user=profile.main_user,
        file_public_key=profile.client.public_key_text,
        file_host_public_key=profile.host.public_key_text,
        file_host_key_fingerprint=profile.host.fingerprint,
        shell_public_key=profile.shell_client.public_key_text,
        shell_host_public_key=profile.shell_host.public_key_text,
        shell_host_key_fingerprint=profile.shell_host.fingerprint,
        fleet_signing_public_key=signing.public_key_text,
        manifest=manifest,
        signature=signature,
    )


def ensure_master_fleet_bootstrap(
    conn: sqlite3.Connection,
    *,
    hostname: str,
    ip: str,
    main_user: str | None = None,
) -> MasterFleetBootstrap:
    """Create the permanent master identity and Generation 1 exactly once."""
    if not _HOSTNAME_RE.fullmatch(hostname):
        raise FleetBootstrapError("Master hostname is invalid")

    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise FleetBootstrapError("Master IP is invalid") from exc

    resolved_user = main_user or resolve_local_main_user()

    try:
        profile = ensure_local_file_profile(resolved_user)
        signing = ensure_fleet_signing_identity(_signing_dir())
    except Exception as exc:
        raise FleetBootstrapError(
            f"Could not prepare master cryptographic identity: {exc}"
        ) from exc

    row = conn.execute(
        """
        SELECT
            fleet_id,
            generation,
            manifest,
            signature,
            signing_public_key
        FROM fleet_state
        WHERE id = 1
        """
    ).fetchone()

    if row is not None:
        fleet_id = _uuid4(row[0], "saved fleet ID")
        generation = int(row[1])
        signature = str(row[3])
        saved_signing_key = str(row[4])

        if saved_signing_key != signing.public_key_text:
            raise FleetBootstrapError(
                "Fleet signing key does not match the pinned fleet state"
            )

        try:
            manifest = normalize_manifest(json.loads(row[2]))
        except (json.JSONDecodeError, FleetManifestError) as exc:
            raise FleetBootstrapError(
                "Saved fleet manifest is invalid"
            ) from exc

        if manifest["fleet_id"] != fleet_id:
            raise FleetBootstrapError(
                "Saved fleet ID does not match its manifest"
            )

        if manifest["generation"] != generation:
            raise FleetBootstrapError(
                "Saved fleet generation does not match its manifest"
            )

        if not verify_manifest(
            manifest,
            signature,
            saved_signing_key,
        ):
            raise FleetBootstrapError(
                "Saved fleet manifest signature is invalid"
            )

        member = next(
            (
                item
                for item in manifest["members"]
                if item["node_id"] == profile.node_id
            ),
            None,
        )

        if member is None or member["role"] != "master":
            raise FleetBootstrapError(
                "Saved fleet does not contain this master identity"
            )

        if (
            member["file_public_key"]
            != profile.client.public_key_text
            or member["file_host_public_key"]
            != profile.host.public_key_text
            or member["file_host_key_fingerprint"]
            != profile.host.fingerprint
            or member.get("shell_public_key") != profile.shell_client.public_key_text
            or member.get("shell_host_public_key") != profile.shell_host.public_key_text
            or member.get("shell_host_key_fingerprint") != profile.shell_host.fingerprint
        ):
            raise FleetBootstrapError(
                "Master file identity changed outside fleet rekey"
            )

        conn.execute(
            """
            UPDATE fleet_nodes
            SET hostname = ?,
                main_user = ?,
                main_uid = ?,
                main_gid = ?,
                last_known_ip = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ?
              AND role = 'master'
            """,
            (
                hostname,
                profile.main_user,
                profile.main_uid,
                profile.main_gid,
                normalized_ip,
                profile.node_id,
            ),
        )

        return _return_bootstrap(
            fleet_id=fleet_id,
            generation=generation,
            hostname=hostname,
            profile=profile,
            signing=signing,
            manifest=manifest,
            signature=signature,
        )

    fleet_id = str(uuid.uuid4())
    generation = 1

    manifest = normalize_manifest(
        {
            "schema_version": 1,
            "fleet_id": fleet_id,
            "generation": generation,
            "members": [
                _master_member(profile, hostname)
            ],
            "revoked": [],
        }
    )

    signature = sign_manifest(
        manifest,
        signing.private_key,
    )

    if not verify_manifest(
        manifest,
        signature,
        signing.public_key_text,
    ):
        raise FleetBootstrapError(
            "New fleet manifest failed self-verification"
        )

    conn.execute(
        """
        INSERT INTO fleet_nodes (
            node_id,
            worker_id,
            hostname,
            role,
            main_user,
            main_uid,
            main_gid,
            file_public_key,
            file_key_generation,
            file_host_public_key,
            file_host_key_fingerprint,
            shell_public_key,
            shell_key_generation,
            shell_host_public_key,
            shell_host_key_fingerprint,
            last_known_ip,
            membership_state,
            membership_generation,
            revoked_at
        )
        VALUES (
            ?, NULL, ?, 'master', ?, ?, ?,
            ?, 1, ?, ?, ?, 1, ?, ?, ?, 'active', 1, NULL
        )
        """,
        (
            profile.node_id,
            hostname,
            profile.main_user,
            profile.main_uid,
            profile.main_gid,
            profile.client.public_key_text,
            profile.host.public_key_text,
            profile.host.fingerprint,
            profile.shell_client.public_key_text,
            profile.shell_host.public_key_text,
            profile.shell_host.fingerprint,
            normalized_ip,
        ),
    )

    conn.execute(
        """
        INSERT INTO fleet_state (
            id,
            fleet_id,
            generation,
            manifest,
            signature,
            signing_public_key
        )
        VALUES (1, ?, ?, ?, ?, ?)
        """,
        (
            fleet_id,
            generation,
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ),
            signature,
            signing.public_key_text,
        ),
    )

    return _return_bootstrap(
        fleet_id=fleet_id,
        generation=generation,
        hostname=hostname,
        profile=profile,
        signing=signing,
        manifest=manifest,
        signature=signature,
    )
