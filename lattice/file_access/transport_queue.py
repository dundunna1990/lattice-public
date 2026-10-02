"""Queue committed signed fleet state for root-side file transport."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from lattice.file_access.manifest import (
    FleetManifestError,
    canonical_manifest_bytes,
    normalize_manifest,
)


DEFAULT_REQUEST_PATH = Path(
    "/var/lib/lattice/file-transport-request.json"
)


class FileTransportQueueError(RuntimeError):
    pass


def _request_path() -> Path:
    override = os.environ.get(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH"
    )
    return (
        Path(override)
        if override
        else DEFAULT_REQUEST_PATH
    )


def _read_existing(path: Path) -> dict | None:
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FileTransportQueueError(
            f"Could not safely open existing request: {exc}"
        ) from exc

    try:
        metadata = os.fstat(descriptor)

        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise FileTransportQueueError(
                "Existing transport request is unsafe"
            )

        if metadata.st_mode & 0o022:
            raise FileTransportQueueError(
                "Existing transport request permissions are unsafe"
            )

        if metadata.st_size > 524288:
            raise FileTransportQueueError(
                "Existing transport request is too large"
            )

        raw = os.read(descriptor, 524289)
    finally:
        os.close(descriptor)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise FileTransportQueueError(
            "Existing transport request is invalid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise FileTransportQueueError(
            "Existing transport request is invalid"
        )

    return payload


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
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

        os.replace(
            temporary,
            path,
        )
        os.chmod(path, 0o600)

    except Exception:
        temporary.unlink(
            missing_ok=True
        )
        raise


def queue_transport_reconcile(
    manifest_payload: object,
    signature: str,
) -> bool:
    """Queue only the newest committed signed generation.

    Returns True when a new request was written and False when an identical
    or newer request was already queued.
    """
    try:
        manifest = normalize_manifest(
            manifest_payload
        )
    except FleetManifestError as exc:
        raise FileTransportQueueError(
            f"Transport manifest is invalid: {exc}"
        ) from exc

    if (
        not isinstance(signature, str)
        or "BEGIN SSH SIGNATURE" not in signature
        or "END SSH SIGNATURE" not in signature
    ):
        raise FileTransportQueueError(
            "Transport manifest signature is invalid"
        )

    path = _request_path()
    existing = _read_existing(path)

    if existing is not None:
        try:
            old_manifest = normalize_manifest(
                existing["manifest"]
            )
            old_signature = str(
                existing["signature"]
            )
        except (
            KeyError,
            FleetManifestError,
        ) as exc:
            raise FileTransportQueueError(
                "Existing transport request cannot be trusted"
            ) from exc

        old_generation = int(
            old_manifest["generation"]
        )
        new_generation = int(
            manifest["generation"]
        )

        if old_generation > new_generation:
            return False

        if old_generation == new_generation:
            if (
                canonical_manifest_bytes(
                    old_manifest
                )
                == canonical_manifest_bytes(
                    manifest
                )
                and old_signature == signature
            ):
                return False

            raise FileTransportQueueError(
                "Conflicting transport state exists for the same generation"
            )

    _atomic_write(
        path,
        {
            "manifest": manifest,
            "signature": signature,
        },
    )

    return True
