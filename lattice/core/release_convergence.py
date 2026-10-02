"""Post-start proof that a restarted Lattice unit is using the active release."""

from __future__ import annotations

from pathlib import Path
import sys


ACTIVE_ROOT = Path("/opt/lattice")


class ReleaseConvergenceError(RuntimeError):
    pass


def verify_active_release(
    *,
    active_root: Path = ACTIVE_ROOT,
    module_path: Path | None = None,
    venv_prefix: Path | None = None,
) -> Path:
    """Fail unless loaded code and the active venv belong to /opt/lattice."""
    try:
        active = active_root.resolve(strict=True)
    except OSError as exc:
        raise ReleaseConvergenceError(
            f"Active Lattice release cannot be resolved: {exc}"
        ) from exc

    module = (module_path or Path(__file__)).resolve()
    prefix = (venv_prefix or Path(sys.prefix)).resolve()
    if active not in module.parents:
        raise ReleaseConvergenceError(
            f"Loaded Lattice code is not from active release {active}: {module}"
        )
    if prefix != active and active not in prefix.parents:
        raise ReleaseConvergenceError(
            f"Python virtual environment is not from active release {active}: {prefix}"
        )
    return active


def main() -> None:
    active = verify_active_release()
    print(f"Lattice release convergence verified: {active}")


if __name__ == "__main__":
    main()
