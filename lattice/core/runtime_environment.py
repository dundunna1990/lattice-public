"""Fail-closed validation for path overrides in an installed Lattice runtime."""

from __future__ import annotations

import os
from pathlib import Path


_CANONICAL_PATH_OVERRIDES = {
    "LATTICE_CONFIG_PATH": "/etc/lattice/lattice.toml",
    "LATTICE_DB_PATH": "/var/lib/lattice/state.sqlite",
    "LATTICE_SOCKET_PATH": "/run/lattice/master.sock",
    "LATTICE_OPERATOR_SOCKET": "/run/lattice-operator/operator.sock",
    "LATTICE_PKI_DIR": "/etc/lattice/pki",
    "LATTICE_FLEET_SIGNING_DIR": "/etc/lattice/fleet-signing",
    "LATTICE_FLEET_BOOTSTRAP_PATH": "/etc/lattice/fleet/bootstrap.json",
    "LATTICE_FLEET_CACHE_PATH": "/var/lib/lattice/fleet/manifest.json",
}


class RuntimeEnvironmentError(RuntimeError):
    """Raised when an installed daemon receives a test-only path override."""


def _is_installed_runtime(module_path: Path | None = None) -> bool:
    path = (module_path or Path(__file__)).resolve()
    text = str(path)
    return text.startswith("/opt/lattice-releases/") or text.startswith("/opt/lattice/")


def validate_production_path_overrides(
    *,
    environ: dict[str, str] | None = None,
    module_path: Path | None = None,
) -> None:
    """Reject non-canonical LATTICE_*_PATH/LATTICE_*_DIR values in /opt."""
    if not _is_installed_runtime(module_path):
        return

    values = os.environ if environ is None else environ
    invalid: list[str] = []
    for name, value in values.items():
        if not name.startswith("LATTICE_"):
            continue
        if not (name.endswith("_PATH") or name.endswith("_DIR")):
            continue
        expected = _CANONICAL_PATH_OVERRIDES.get(name)
        if expected is None or value != expected:
            invalid.append(name)

    if invalid:
        names = ", ".join(sorted(invalid))
        raise RuntimeEnvironmentError(
            "Installed Lattice refuses test-only or non-canonical path "
            f"overrides: {names}. Remove them from the service environment."
        )


def main() -> None:
    validate_production_path_overrides()


if __name__ == "__main__":
    main()
