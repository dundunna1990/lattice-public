"""Persistent state for safe network changes."""

import json
import os
import tempfile
import stat
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_STATE_PATH = Path("/var/lib/lattice-root/ipchange.state")
DEFAULT_ORIGINAL_STATE_PATH = Path("/var/lib/lattice-root/ipchange.original.json")
DEFAULT_EXPECTED_PATH = Path("/etc/lattice/network.json")


def _state_path():
    return Path(os.environ.get("LATTICE_IP_STATE_PATH", DEFAULT_STATE_PATH))


def _original_state_path():
    return Path(
        os.environ.get(
            "LATTICE_IP_ORIGINAL_STATE_PATH",
            DEFAULT_ORIGINAL_STATE_PATH,
        )
    )


def _expected_path():
    return Path(os.environ.get("LATTICE_EXPECTED_NETWORK_PATH", DEFAULT_EXPECTED_PATH))


def _read(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"Unsafe Lattice state file: {path}")
        if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
            raise RuntimeError(f"Unsafe ownership or permissions on Lattice state file: {path}")
        if metadata.st_size > 1024 * 1024:
            raise RuntimeError(f"Lattice state file is too large: {path}")
        raw = os.read(descriptor, metadata.st_size + 1)
    finally:
        os.close(descriptor)
    return json.loads(raw.decode("utf-8"))


def _write(path, data, mode=0o600):
    """Atomically write private JSON so a power loss cannot leave half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        path.chmod(mode)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def read_state():
    return _read(_state_path())


def read_original_network_state():
    """Read the immutable pre-Lattice network snapshot."""
    return _read(_original_state_path())


def preserve_original_network_state(data):
    """Atomically create the pre-Lattice snapshot without overwriting it."""
    path = _original_state_path()

    existing = _read(path)
    if existing is not None:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )

    try:
        os.fchmod(descriptor, 0o600)

        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                data,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        try:
            # Hard-link creation is atomic and refuses to replace an
            # already-existing original snapshot.
            os.link(temp_name, path)
        except FileExistsError:
            # Validate the winner rather than overwriting it.
            _read(path)
            return False

        try:
            directory = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass

        return True
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def quarantine_state_file():
    """Preserve an unreadable recovery file instead of deleting it."""
    path = _state_path()

    if not path.exists():
        return None

    stamp = (
        datetime.now(timezone.utc)
        .strftime("%Y%m%dT%H%M%SZ")
    )

    candidate = path.with_name(
        f"{path.name}.corrupt-{stamp}"
    )

    suffix = 0

    while candidate.exists():
        suffix += 1
        candidate = path.with_name(
            f"{path.name}.corrupt-{stamp}-{suffix}"
        )

    os.replace(path, candidate)

    # Persist the directory rename when supported.
    try:
        descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        pass

    return candidate


def write_state(data):
    _write(_state_path(), data)


def clear_state():
    try:
        _state_path().unlink()
    except FileNotFoundError:
        pass


def read_expected_network():
    return _read(_expected_path())


def write_expected_network(data):
    # This contains only network addresses, not credentials. The unprivileged
    # master/worker daemon must be able to read it for drift monitoring.
    _write(_expected_path(), data, mode=0o644)


def clear_expected_network():
    try:
        _expected_path().unlink()
    except FileNotFoundError:
        pass
