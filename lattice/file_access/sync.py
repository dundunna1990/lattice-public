"""Worker-side verification and durable caching of signed fleet generations."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import pwd

from lattice.file_access.bootstrap import (
    FleetBootstrapError,
    validate_master_bootstrap,
)
from lattice.file_access.identity import (
    load_node_identity,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    canonical_manifest_bytes,
    normalize_manifest,
    require_newer_generation,
    verify_manifest,
)
from lattice.file_access.profile import (
    ensure_local_file_profile,
)


DEFAULT_FLEET_BOOTSTRAP_PATH = Path(
    "/etc/lattice/fleet/bootstrap.json"
)
DEFAULT_FLEET_CACHE_PATH = Path(
    "/var/lib/lattice/fleet/manifest.json"
)


class FleetSyncError(RuntimeError):
    """Raised when a signed fleet generation cannot be trusted."""


def _bootstrap_path() -> Path:
    override = os.environ.get(
        "LATTICE_FLEET_BOOTSTRAP_PATH"
    )
    return (
        Path(override)
        if override
        else DEFAULT_FLEET_BOOTSTRAP_PATH
    )


def _cache_path() -> Path:
    override = os.environ.get(
        "LATTICE_FLEET_CACHE_PATH"
    )
    return (
        Path(override)
        if override
        else DEFAULT_FLEET_CACHE_PATH
    )


def _safe_read_json(path: Path, maximum: int = 262144, *, allow_lattice_owner: bool = False) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FleetSyncError(
            f"Could not safely open {path}: {exc}"
        ) from exc

    try:
        metadata = os.fstat(descriptor)

        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise FleetSyncError(
                f"{path} is not a single regular file"
            )

        allowed_uids = {0, os.geteuid()}
        if allow_lattice_owner:
            try:
                allowed_uids.add(pwd.getpwnam("lattice").pw_uid)
            except KeyError:
                pass
        if metadata.st_uid not in allowed_uids:
            raise FleetSyncError(
                f"{path} has unexpected ownership"
            )

        if metadata.st_mode & 0o022:
            raise FleetSyncError(
                f"{path} is writable by group or others"
            )

        if metadata.st_size > maximum:
            raise FleetSyncError(
                f"{path} is unexpectedly large"
            )

        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise FleetSyncError(
            f"{path} is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise FleetSyncError(
            f"{path} does not contain a JSON object"
        )

    return payload


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )

    temporary = Path(temporary_name)

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(
                payload,
                handle,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def load_pinned_fleet_bootstrap() -> dict[str, str]:
    payload = _safe_read_json(_bootstrap_path())

    try:
        return validate_master_bootstrap(
            fleet_id=payload.get("fleet_id"),
            master_node_id=payload.get(
                "master_node_id"
            ),
            master_file_public_key=payload.get(
                "master_file_public_key"
            ),
            master_file_host_public_key=payload.get(
                "master_file_host_public_key"
            ),
            master_file_host_key_fingerprint=payload.get(
                "master_file_host_key_fingerprint"
            ),
            master_shell_public_key=payload.get("master_shell_public_key"),
            master_shell_host_public_key=payload.get("master_shell_host_public_key"),
            master_shell_host_key_fingerprint=payload.get("master_shell_host_key_fingerprint"),
            fleet_signing_public_key=payload.get(
                "fleet_signing_public_key"
            ),
        )
    except FleetBootstrapError as exc:
        raise FleetSyncError(
            f"Pinned fleet bootstrap is invalid: {exc}"
        ) from exc


def _validate_master_member(
    manifest: dict,
    bootstrap: dict[str, str],
) -> None:
    master = next(
        (
            member
            for member in manifest["members"]
            if member["node_id"]
            == bootstrap["master_node_id"]
        ),
        None,
    )

    if master is None or master["role"] != "master":
        raise FleetSyncError(
            "Signed fleet generation does not contain the pinned master"
        )

    expected = {
        "file_public_key":
            bootstrap["master_file_public_key"],
        "file_host_public_key":
            bootstrap["master_file_host_public_key"],
        "file_host_key_fingerprint":
            bootstrap["master_file_host_key_fingerprint"],
    }

    for field, value in expected.items():
        if master[field] != value:
            raise FleetSyncError(
                f"Signed fleet generation changed pinned master {field}"
            )


def _validate_local_member(manifest: dict) -> str:
    identity = load_node_identity()

    if identity is None:
        raise FleetSyncError(
            "Local permanent node identity is missing"
        )

    profile = ensure_local_file_profile(
        identity.main_user
    )

    local = next(
        (
            member
            for member in manifest["members"]
            if member["node_id"] == identity.node_id
        ),
        None,
    )

    if local is None:
        raise FleetSyncError(
            "Signed fleet generation does not contain this computer"
        )

    if local["role"] != "worker":
        raise FleetSyncError(
            "This worker is assigned the wrong fleet role"
        )

    expected = {
        "main_user": identity.main_user,
        "file_public_key":
            profile.client.public_key_text,
        "file_host_public_key":
            profile.host.public_key_text,
        "file_host_key_fingerprint":
            profile.host.fingerprint,
    }
    if local.get("shell_public_key") is not None:
        expected.update({
            "shell_public_key": profile.shell_client.public_key_text,
            "shell_host_public_key": profile.shell_host.public_key_text,
            "shell_host_key_fingerprint": profile.shell_host.fingerprint,
        })

    for field, value in expected.items():
        if local[field] != value:
            raise FleetSyncError(
                f"Signed fleet generation contains the wrong local {field}"
            )

    return identity.node_id


def _load_cached_generation(
    bootstrap: dict[str, str],
) -> tuple[dict, str] | None:
    path = _cache_path()

    if not path.exists():
        return None

    payload = _safe_read_json(path, allow_lattice_owner=True)

    try:
        manifest = normalize_manifest(
            payload["manifest"]
        )
        signature = str(payload["signature"])
    except (
        KeyError,
        FleetManifestError,
    ) as exc:
        raise FleetSyncError(
            "Cached fleet generation is invalid"
        ) from exc

    if manifest["fleet_id"] != bootstrap["fleet_id"]:
        raise FleetSyncError(
            "Cached fleet ID does not match the pinned fleet"
        )

    if not verify_manifest(
        manifest,
        signature,
        bootstrap["fleet_signing_public_key"],
    ):
        raise FleetSyncError(
            "Cached fleet generation has an invalid signature"
        )

    return manifest, signature


def get_cached_signed_manifest() -> tuple[dict, str] | None:
    """Return the already-verified cached fleet generation.

    This does not make a new trust decision. The caller uses it only after
    the master confirms that the same generation is committed.
    """
    bootstrap = load_pinned_fleet_bootstrap()
    return _load_cached_generation(bootstrap)


def get_cached_fleet_generation() -> int:
    """Return the locally cached generation as a heartbeat status hint.

    The signed manifest was cryptographically verified before being written.
    This lightweight read intentionally avoids spawning ssh-keygen on every
    ten-second heartbeat. The master never treats this value as a new trust
    decision; it only uses it to decide whether this peer needs a newer
    signed manifest.
    """
    path = _cache_path()

    if not path.exists():
        return 0

    payload = _safe_read_json(path, allow_lattice_owner=True)

    try:
        manifest = normalize_manifest(
            payload["manifest"]
        )
    except (
        KeyError,
        FleetManifestError,
    ) as exc:
        raise FleetSyncError(
            "Cached fleet generation is invalid"
        ) from exc

    return int(manifest["generation"])


def apply_signed_manifest(
    manifest_payload: object,
    signature: str,
) -> dict[str, object]:
    """Verify and atomically cache one master-signed fleet generation."""
    bootstrap = load_pinned_fleet_bootstrap()

    try:
        manifest = normalize_manifest(
            manifest_payload
        )
    except FleetManifestError as exc:
        raise FleetSyncError(
            f"Fleet generation is invalid: {exc}"
        ) from exc

    if manifest["fleet_id"] != bootstrap["fleet_id"]:
        raise FleetSyncError(
            "Fleet generation belongs to a different fleet"
        )

    if not verify_manifest(
        manifest,
        signature,
        bootstrap["fleet_signing_public_key"],
    ):
        raise FleetSyncError(
            "Fleet generation signature is invalid"
        )

    _validate_master_member(
        manifest,
        bootstrap,
    )

    local_node_id = _validate_local_member(
        manifest
    )

    cached = _load_cached_generation(
        bootstrap
    )

    if cached is not None:
        current_manifest, current_signature = cached

        if (
            manifest["generation"]
            == current_manifest["generation"]
        ):
            if (
                canonical_manifest_bytes(manifest)
                == canonical_manifest_bytes(
                    current_manifest
                )
                and signature == current_signature
            ):
                return {
                    "status": "already_current",
                    "generation": manifest["generation"],
                    "node_id": local_node_id,
                }

            raise FleetSyncError(
                "Conflicting data was supplied for an existing generation"
            )

        try:
            require_newer_generation(
                current_manifest["generation"],
                manifest,
            )
        except FleetManifestError as exc:
            raise FleetSyncError(
                str(exc)
            ) from exc

    _atomic_write_json(
        _cache_path(),
        {
            "manifest": manifest,
            "signature": signature,
        },
    )

    return {
        "status": "applied",
        "generation": manifest["generation"],
        "node_id": local_node_id,
    }
