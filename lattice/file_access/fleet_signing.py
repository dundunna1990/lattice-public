"""Root-isolated signing for runtime fleet-key rotations."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys

from lattice.file_access.keys import (
    DEFAULT_FLEET_SIGNING_DIR,
    ensure_fleet_signing_identity,
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import (
    normalize_manifest,
    sign_manifest,
    verify_manifest,
)


SIGN_SOCKET = Path("/run/lattice/fleet-sign.sock")
STATE_DB = Path("/var/lib/lattice/state.sqlite")
ROLE_PATH = Path("/etc/lattice/role")
PRIVATE_KEY = DEFAULT_FLEET_SIGNING_DIR / "fleet_signing_ed25519"
PUBLIC_KEY = DEFAULT_FLEET_SIGNING_DIR / "fleet_signing_ed25519.pub"

MAX_REQUEST_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 128 * 1024

_ALLOWED_OPERATIONS = {
    "file-overlap",
    "file-finalize",
    "shell-overlap",
    "shell-finalize",
}

_FILE_CURRENT = (
    "file_public_key",
    "file_host_public_key",
    "file_host_key_fingerprint",
    "file_key_generation",
)
_FILE_NEXT = (
    "file_next_public_key",
    "file_next_host_public_key",
    "file_next_host_key_fingerprint",
    "file_next_key_generation",
)
_SHELL_CURRENT = (
    "shell_public_key",
    "shell_host_public_key",
    "shell_host_key_fingerprint",
    "shell_key_generation",
)
_SHELL_NEXT = (
    "shell_next_public_key",
    "shell_next_host_public_key",
    "shell_next_host_key_fingerprint",
    "shell_next_key_generation",
)
_ALL_NEXT = _FILE_NEXT + _SHELL_NEXT


class FleetSigningError(RuntimeError):
    """Raised when a fleet-signing request is unsafe or cannot be completed."""


def _identity(public_key: str) -> str:
    value = validate_ed25519_public_key(public_key)
    return " ".join(value.split()[:2])


def _verify(payload: dict, signature: str, public_key: str) -> bool:
    try:
        return bool(verify_manifest(payload, signature, public_key))
    except Exception:
        return False


def _fields(channel: str):
    if channel == "file":
        return _FILE_CURRENT, _FILE_NEXT
    if channel == "shell":
        return _SHELL_CURRENT, _SHELL_NEXT
    raise FleetSigningError(f"Unsupported rotation channel: {channel}")


def validate_rotation_transition(
    operation: str,
    target_node_id: str,
    current_manifest: object,
    candidate_manifest: object,
) -> dict:
    """Allow only one exact file/shell key-rotation generation transition."""
    if operation not in _ALLOWED_OPERATIONS:
        raise FleetSigningError("Fleet signing operation is not permitted")

    channel, phase = operation.rsplit("-", 1)
    current_fields, next_fields = _fields(channel)

    try:
        current = normalize_manifest(current_manifest)
        candidate = normalize_manifest(candidate_manifest)
    except Exception as exc:
        raise FleetSigningError(
            f"Fleet manifest is invalid: {exc}"
        ) from exc

    if candidate["schema_version"] != current["schema_version"]:
        raise FleetSigningError(
            "Fleet schema may not change during key rotation"
        )
    if candidate["fleet_id"] != current["fleet_id"]:
        raise FleetSigningError(
            "Fleet ID may not change during key rotation"
        )
    if candidate["generation"] != current["generation"] + 1:
        raise FleetSigningError(
            "Rotation must advance the fleet by exactly one generation"
        )
    if candidate["revoked"] != current["revoked"]:
        raise FleetSigningError(
            "Revocation state may not change during key rotation"
        )

    current_members = {
        item["node_id"]: item
        for item in current["members"]
    }
    candidate_members = {
        item["node_id"]: item
        for item in candidate["members"]
    }

    if current_members.keys() != candidate_members.keys():
        raise FleetSigningError(
            "Fleet membership may not change during key rotation"
        )

    if target_node_id not in current_members:
        raise FleetSigningError(
            "Rotation target is not an active fleet member"
        )

    # Root signer independently enforces one rotation at a time.
    for node_id, member in current_members.items():
        present = {
            field
            for field in _ALL_NEXT
            if field in member
        }

        if phase == "overlap":
            if present:
                raise FleetSigningError(
                    "A key rotation is already staged "
                    "in the current fleet generation"
                )

        elif phase == "finalize":
            if node_id == target_node_id:
                if present != set(next_fields):
                    raise FleetSigningError(
                        "Finalization requires exactly one "
                        "matching staged rotation"
                    )
            elif present:
                raise FleetSigningError(
                    "Another fleet member has a staged rotation"
                )
        else:
            raise FleetSigningError(
                "Unknown rotation phase"
            )

    # Every non-target member must be byte-for-byte equivalent
    # after manifest normalization.
    for node_id in current_members:
        if node_id == target_node_id:
            continue

        if (
            current_members[node_id]
            != candidate_members[node_id]
        ):
            raise FleetSigningError(
                "Key rotation may not modify another fleet member"
            )

    current_target = current_members[target_node_id]
    candidate_target = candidate_members[target_node_id]

    if phase == "overlap":
        if any(
            field not in candidate_target
            for field in next_fields
        ):
            raise FleetSigningError(
                "Candidate overlap identity is incomplete"
            )

        if (
            candidate_target[next_fields[-1]]
            != current_target[current_fields[-1]] + 1
        ):
            raise FleetSigningError(
                "Next key generation is not sequential"
            )

        expected_target = copy.deepcopy(current_target)

        for field in next_fields:
            expected_target[field] = candidate_target[field]

        if candidate_target != expected_target:
            raise FleetSigningError(
                "Overlap generation changes fields outside "
                "the requested key rotation"
            )

    else:
        expected_target = copy.deepcopy(current_target)

        for current_field, next_field in zip(
            current_fields,
            next_fields,
        ):
            expected_target[current_field] = (
                current_target[next_field]
            )

        for next_field in next_fields:
            expected_target.pop(next_field, None)

        if candidate_target != expected_target:
            raise FleetSigningError(
                "Final generation does not exactly promote "
                "the staged key rotation"
            )

    return candidate


def _require_secure_root_file(
    path: Path,
    *,
    exact_mode: int | None = None,
    forbid_write_mask: int = 0o022,
):
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FleetSigningError(
            f"Could not inspect protected file {path}: {exc}"
        ) from exc

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
    ):
        raise FleetSigningError(
            f"Protected file is not a root-owned "
            f"regular file: {path}"
        )

    mode = stat.S_IMODE(metadata.st_mode)

    if exact_mode is not None and mode != exact_mode:
        raise FleetSigningError(
            f"Protected file has unsafe mode {mode:o}; "
            f"expected {exact_mode:o}: {path}"
        )

    if (
        exact_mode is None
        and mode & forbid_write_mask
    ):
        raise FleetSigningError(
            f"Protected file is writable by group/others: {path}"
        )

    return metadata


def _require_master_role() -> None:
    _require_secure_root_file(
        ROLE_PATH,
        forbid_write_mask=0o022,
    )

    try:
        role = ROLE_PATH.read_text(
            encoding="utf-8"
        ).strip()
    except OSError as exc:
        raise FleetSigningError(
            f"Could not read Lattice role: {exc}"
        ) from exc

    if role != "master":
        raise FleetSigningError(
            "Fleet signing is available only "
            "on the Lattice Master"
        )


def _root_signing_public_key() -> str:
    try:
        directory = (
            DEFAULT_FLEET_SIGNING_DIR.lstat()
        )
    except OSError as exc:
        raise FleetSigningError(
            f"Could not inspect fleet-signing directory: {exc}"
        ) from exc

    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != 0
        or directory.st_gid != 0
        or stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise FleetSigningError(
            "Fleet-signing directory must remain "
            "root:root mode 0700"
        )

    _require_secure_root_file(
        PRIVATE_KEY,
        exact_mode=0o600,
    )
    _require_secure_root_file(
        PUBLIC_KEY,
        forbid_write_mask=0o022,
    )

    try:
        public_key = validate_ed25519_public_key(
            PUBLIC_KEY.read_text(
                encoding="utf-8"
            ).strip()
        )
    except Exception as exc:
        raise FleetSigningError(
            f"Fleet signing public key is invalid: {exc}"
        ) from exc

    try:
        derived = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-y",
                "-f",
                str(PRIVATE_KEY),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise FleetSigningError(
            f"Could not inspect fleet signing private key: {exc}"
        ) from exc

    if derived.returncode != 0:
        detail = (
            derived.stderr
            or derived.stdout
            or "ssh-keygen failed"
        ).strip()

        raise FleetSigningError(
            f"Could not derive fleet signing public key: {detail}"
        )

    try:
        derived_public = (
            validate_ed25519_public_key(
                derived.stdout.strip()
            )
        )
    except Exception as exc:
        raise FleetSigningError(
            "Fleet signing private key is invalid"
        ) from exc

    if (
        _identity(derived_public)
        != _identity(public_key)
    ):
        raise FleetSigningError(
            "Fleet signing public/private keypair "
            "does not match"
        )

    return public_key


def _read_current_state():
    conn = None

    try:
        conn = sqlite3.connect(
            f"file:{STATE_DB}?mode=ro",
            uri=True,
            timeout=5,
        )
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT manifest, signature, signing_public_key "
            "FROM fleet_state WHERE id=1"
        ).fetchone()

    except sqlite3.Error as exc:
        raise FleetSigningError(
            f"Could not read current fleet state: {exc}"
        ) from exc

    finally:
        if conn is not None:
            conn.close()

    if row is None:
        raise FleetSigningError(
            "Master fleet state is unavailable"
        )

    try:
        manifest = normalize_manifest(
            json.loads(row["manifest"])
        )
        public_key = (
            validate_ed25519_public_key(
                str(row["signing_public_key"])
            )
        )
    except Exception as exc:
        raise FleetSigningError(
            f"Saved fleet state is invalid: {exc}"
        ) from exc

    return (
        manifest,
        str(row["signature"]),
        public_key,
    )


def _request_signer(request: dict) -> str:
    payload = (
        json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")

    if len(payload) > MAX_REQUEST_BYTES:
        raise FleetSigningError(
            "Fleet signing request is too large"
        )

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as client:
            client.settimeout(30)
            client.connect(str(SIGN_SOCKET))
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)

            chunks = []
            size = 0

            while True:
                chunk = client.recv(65536)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_RESPONSE_BYTES:
                    raise FleetSigningError(
                        "Fleet signing response is too large"
                    )

                chunks.append(chunk)

    except (OSError, TimeoutError) as exc:
        raise FleetSigningError(
            f"Fleet signing service is unavailable: {exc}"
        ) from exc

    try:
        response = json.loads(
            b"".join(chunks).decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise FleetSigningError(
            "Fleet signing service returned "
            "an invalid response"
        ) from exc

    if (
        not isinstance(response, dict)
        or response.get("ok") is not True
    ):
        detail = (
            response.get("error")
            if isinstance(response, dict)
            else None
        )

        raise FleetSigningError(
            "Fleet signing service refused the request: "
            f"{detail or 'unknown error'}"
        )

    signature = response.get("signature")

    if not isinstance(signature, str):
        raise FleetSigningError(
            "Fleet signing service omitted the signature"
        )

    return signature


def sign_rotation_manifest(
    operation: str,
    target_node_id: str,
    manifest: object,
    signing_public_key: str,
) -> str:
    """
    Sign one runtime key-rotation generation without
    exposing the production root private key.
    """
    if operation not in _ALLOWED_OPERATIONS:
        raise FleetSigningError(
            "Fleet signing operation is not permitted"
        )

    candidate = normalize_manifest(manifest)

    if target_node_id not in {
        member["node_id"]
        for member in candidate["members"]
    }:
        raise FleetSigningError(
            "Rotation target is not in the candidate fleet"
        )

    public_key = validate_ed25519_public_key(
        signing_public_key
    )

    # Existing unit tests use an explicit temporary signing
    # directory. Production never takes this branch.
    override = os.environ.get(
        "LATTICE_FLEET_SIGNING_DIR"
    )

    if (
        override
        and Path(override)
        != DEFAULT_FLEET_SIGNING_DIR
    ):
        signing = ensure_fleet_signing_identity(
            Path(override)
        )

        if (
            _identity(signing.public_key_text)
            != _identity(public_key)
        ):
            raise FleetSigningError(
                "Fixture signing key does not match "
                "pinned fleet state"
            )

        signature = sign_manifest(
            candidate,
            signing.private_key,
        )

    else:
        signature = _request_signer(
            {
                "operation": operation,
                "target_node_id": target_node_id,
                "manifest": candidate,
            }
        )

    if not _verify(
        candidate,
        signature,
        public_key,
    ):
        raise FleetSigningError(
            "Fleet signing service returned "
            "an invalid signature"
        )

    return signature


def privileged_main() -> int:
    """
    Handle one systemd socket-activated signing request.
    This process runs as root.
    """
    try:
        if os.geteuid() != 0:
            raise FleetSigningError(
                "Fleet signing helper must run as root"
            )

        _require_master_role()

        raw = sys.stdin.buffer.read(
            MAX_REQUEST_BYTES + 1
        )

        if len(raw) > MAX_REQUEST_BYTES:
            raise FleetSigningError(
                "Fleet signing request is too large"
            )

        try:
            request = json.loads(
                raw.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise FleetSigningError(
                "Fleet signing request is invalid JSON"
            ) from exc

        if not isinstance(request, dict):
            raise FleetSigningError(
                "Fleet signing request must be an object"
            )

        operation = request.get("operation")
        target_node_id = request.get(
            "target_node_id"
        )

        if (
            not isinstance(operation, str)
            or not isinstance(target_node_id, str)
        ):
            raise FleetSigningError(
                "Fleet signing request is incomplete"
            )

        (
            current,
            current_signature,
            pinned_public_key,
        ) = _read_current_state()

        root_public_key = (
            _root_signing_public_key()
        )

        if (
            _identity(root_public_key)
            != _identity(pinned_public_key)
        ):
            raise FleetSigningError(
                "Root fleet signing key does not match "
                "the pinned fleet state"
            )

        if not _verify(
            current,
            current_signature,
            root_public_key,
        ):
            raise FleetSigningError(
                "Current fleet state signature is invalid"
            )

        candidate = validate_rotation_transition(
            operation,
            target_node_id,
            current,
            request.get("manifest"),
        )

        signature = sign_manifest(
            candidate,
            PRIVATE_KEY,
        )

        if not _verify(
            candidate,
            signature,
            root_public_key,
        ):
            raise FleetSigningError(
                "New fleet signature failed "
                "self-verification"
            )

        response = {
            "ok": True,
            "signature": signature,
        }

        sys.stdout.write(
            json.dumps(
                response,
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stdout.flush()

        return 0

    except Exception as exc:
        response = {
            "ok": False,
            "error": str(exc),
        }

        try:
            sys.stdout.write(
                json.dumps(
                    response,
                    separators=(",", ":"),
                )
                + "\n"
            )
            sys.stdout.flush()
        except Exception:
            pass

        print(
            f"fleet-signing request refused: {exc}",
            file=sys.stderr,
        )

        return 3


if __name__ == "__main__":
    raise SystemExit(privileged_main())
