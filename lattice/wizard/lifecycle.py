"""One-role-only systemd lifecycle used by the guided setup wizard."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Callable


ROLE_PATH = Path("/etc/lattice/role")
MASTER_ROLE = "master"
WORKER_ROLE = "worker"
VALID_ROLES = {MASTER_ROLE, WORKER_ROLE}

# Activation sources whose exact enabled/active state must survive a failed
# role transition.
_TRACKED_UNITS = (
    "lattice-master.service",
    "lattice-worker.service",
    "lattice-network-assignment.path",
    "lattice-network-reconcile.timer",
    "lattice-network-reconcile.service",
    "lattice-health-watchdog.timer",
    "lattice-backup.timer",
    "lattice-care.timer",
    "lattice-backup-maintenance.timer",
    "lattice-backup-alerts.timer",
    "lattice-backup-observation-refresh.timer",
    "lattice-backup-assignment-reconcile.timer",
    "lattice-credential-revoke.path",
    "lattice-file-transport-reconcile.path",
    "lattice-file-sshd.service",
    "lattice-backup-transport-reconcile.path",
    "lattice-backup-run-request.path",
    "lattice-backup-query.path",
    "lattice-backup-restore.path",
    "lattice-backup-sshd.service",
    "lattice-mount-manager.service",
    "lattice-shell-sshd.service",
    "lattice-shell-connection-manager.service",
)

Runner = Callable[..., subprocess.CompletedProcess]


class RoleLifecycleError(RuntimeError):
    """Raised when systemd cannot safely switch this machine to one role."""


def selected_service(role: str) -> str:
    if role not in VALID_ROLES:
        raise RoleLifecycleError(f"Unknown Lattice role: {role!r}")
    return "lattice-master.service" if role == MASTER_ROLE else "lattice-worker.service"


def role_service_commands(role: str) -> list[list[str]]:
    """Return the exact role-transition commands in their required order."""
    role_service = selected_service(role)
    commands = [
        # Stop every role-related activation source before selecting one role.
        ["systemctl", "disable", "--now", "lattice-master.service"],
        ["systemctl", "disable", "--now", "lattice-worker.service"],
        ["systemctl", "disable", "--now", "lattice-network-assignment.path"],
        ["systemctl", "disable", "--now", "lattice-network-reconcile.timer"],
        ["systemctl", "stop", "lattice-network-reconcile.service"],
        ["systemctl", "disable", "--now", "lattice-health-watchdog.timer"],
        ["systemctl", "disable", "--now", "lattice-backup.timer"],
        ["systemctl", "disable", "--now", "lattice-care.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-maintenance.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-alerts.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-observation-refresh.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-assignment-reconcile.timer"],
        ["systemctl", "disable", "--now", "lattice-credential-revoke.path"],
        ["systemctl", "disable", "--now", "lattice-file-transport-reconcile.path"],
        ["systemctl", "disable", "--now", "lattice-file-sshd.service"],
        ["systemctl", "disable", "--now", "lattice-mount-manager.service"],
        ["systemctl", "disable", "--now", "lattice-shell-connection-manager.service"],
        ["systemctl", "disable", "--now", "lattice-shell-sshd.service"],
        ["systemctl", "disable", "--now", "lattice-backup-transport-reconcile.path"],
        ["systemctl", "disable", "--now", "lattice-backup-run-request.path"],
        ["systemctl", "disable", "--now", "lattice-backup-query.path"],
        ["systemctl", "disable", "--now", "lattice-backup-restore.path"],
        ["systemctl", "disable", "--now", "lattice-backup-sshd.service"],
        # Recover an interrupted network operation before initializing state.
        ["systemctl", "enable", "lattice-boot-recovery.service"],
        ["systemctl", "start", "lattice-boot-recovery.service"],
        # Restart the successful one-shot preparation task for each role
        # change so migrations and protected runtime files are refreshed.
        ["systemctl", "restart", "lattice-init.service"],
        ["systemctl", "enable", "--now", role_service],

        # File transport exists on BOTH master and worker roles. The sshd
        # may initially be skipped by its ConditionPathExists; the first
        # successful reconciliation restarts it automatically.
        [
            "systemctl",
            "enable",
            "--now",
            "lattice-file-sshd.service",
        ],
        [
            "systemctl",
            "enable",
            "--now",
            "lattice-file-transport-reconcile.path",
        ],
        [
            "systemctl", "enable", "--now", "lattice-mount-manager.service",
        ],
        [
            "systemctl", "enable", "--now", "lattice-shell-sshd.service",
        ],
        [
            "systemctl", "enable", "--now", "lattice-shell-connection-manager.service",
        ],
        ["systemctl", "enable", "--now", "lattice-backup-sshd.service"],
        ["systemctl", "enable", "--now", "lattice-backup-transport-reconcile.path"],
        ["systemctl", "enable", "--now", "lattice-backup-run-request.path"],
        ["systemctl", "enable", "--now", "lattice-backup-query.path"],
        ["systemctl", "enable", "--now", "lattice-backup-restore.path"],
        ["systemctl", "enable", "--now", "lattice-backup.timer"],
        ["systemctl", "enable", "--now", "lattice-care.timer"],
        ["systemctl", "enable", "--now", "lattice-backup-maintenance.timer"],
    ]
    if role == WORKER_ROLE:
        commands.append(["systemctl", "enable", "--now", "lattice-credential-revoke.path"])
        commands.append(["systemctl", "enable", "--now", "lattice-network-assignment.path"])
        # A fresh Worker has only a temporary LAN address. Permanent-address
        # reconciliation is armed by the root assignment helper only after the
        # authenticated Master assignment has been applied and verified.
    if role == MASTER_ROLE:
        commands.append(["systemctl", "enable", "--now", "lattice-network-reconcile.timer"])
        commands.append(["systemctl", "enable", "--now", "lattice-health-watchdog.timer"])
        commands.append(["systemctl", "enable", "--now", "lattice-backup-alerts.timer"])
        commands.append(["systemctl", "enable", "--now", "lattice-backup-observation-refresh.timer"])
        commands.append(["systemctl", "enable", "--now", "lattice-backup-assignment-reconcile.timer"])
    return commands


def current_role(role_path: Path = ROLE_PATH) -> str | None:
    try:
        value = role_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RoleLifecycleError(f"Could not read Lattice role state: {exc}") from exc
    return value if value in VALID_ROLES else None


def _write_role_file(role: str, role_path: Path) -> None:
    role_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=role_path.parent, prefix=f".{role_path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"{role}\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            os.chown(temporary_path, 0, 0)
            os.chmod(temporary_path, 0o644)
        else:
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, role_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _restore_role_file(role_path: Path, previous: bytes | None) -> None:
    if previous is None:
        role_path.unlink(missing_ok=True)
        return
    descriptor, temporary_name = tempfile.mkstemp(
        dir=role_path.parent, prefix=f".{role_path.name}.restore.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(previous)
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            os.chown(temporary_path, 0, 0)
            os.chmod(temporary_path, 0o644)
        else:
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, role_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _probe_unit(
    runner: Runner,
    action: str,
    unit: str,
) -> bool:
    """Return systemd enabled/active state without treating false as error."""
    try:
        result = runner(
            ["systemctl", action, unit],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RoleLifecycleError(
            f"Could not inspect {unit} before role switch: {exc}"
        ) from exc

    return result.returncode == 0


def _snapshot_unit_states(
    runner: Runner,
) -> dict[str, dict[str, bool]]:
    return {
        unit: {
            "enabled": _probe_unit(
                runner,
                "is-enabled",
                unit,
            ),
            "active": _probe_unit(
                runner,
                "is-active",
                unit,
            ),
        }
        for unit in _TRACKED_UNITS
    }


def _restore_unit_states(
    snapshot: dict[str, dict[str, bool]],
    runner: Runner,
) -> list[str]:
    """Best-effort restoration after a failed role change."""
    errors = []

    def run(command):
        try:
            result = runner(
                command,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            errors.append(
                f"{' '.join(command)}: {exc}"
            )
            return

        if result.returncode != 0:
            detail = (
                result.stderr
                or result.stdout
                or "systemd error"
            ).strip()

            errors.append(
                f"{' '.join(command)}: {detail}"
            )

    # First clear any partial new-role activation.
    for unit in _TRACKED_UNITS:
        run(
            [
                "systemctl",
                "disable",
                "--now",
                unit,
            ]
        )

    # Then restore enabled state.
    for unit, state in snapshot.items():
        if state["enabled"]:
            run(
                [
                    "systemctl",
                    "enable",
                    unit,
                ]
            )

    # Finally restore runtime state.
    for unit, state in snapshot.items():
        if state["active"]:
            run(
                [
                    "systemctl",
                    "start",
                    unit,
                ]
            )

    return errors


def activate_role(
    role: str,
    *,
    runner: Runner = subprocess.run,
    role_path: Path = ROLE_PATH,
) -> None:
    """Select one role, run its required preparation, and restore on failure."""
    commands = role_service_commands(role)

    # Capture the real activation state BEFORE stopping anything.
    previous_units = _snapshot_unit_states(
        runner
    )

    try:
        previous = role_path.read_bytes()
    except FileNotFoundError:
        previous = None

    _write_role_file(role, role_path)

    try:
        for command in commands:
            result = runner(
                command,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                detail = (
                    result.stderr
                    or result.stdout
                    or "unknown systemd error"
                ).strip()

                raise RoleLifecycleError(
                    f"{' '.join(command)} failed: {detail}"
                )

    except (
        OSError,
        subprocess.TimeoutExpired,
        RoleLifecycleError,
    ) as exc:
        # Restore the role identity BEFORE restarting old services so their
        # ExecCondition sees the previous role.
        _restore_role_file(
            role_path,
            previous,
        )

        rollback_errors = (
            _restore_unit_states(
                previous_units,
                runner,
            )
        )

        suffix = ""

        if rollback_errors:
            suffix = (
                " Role rollback also reported: "
                + "; ".join(rollback_errors)
            )

        if isinstance(
            exc,
            RoleLifecycleError,
        ):
            raise RoleLifecycleError(
                f"{exc}{suffix}"
            ) from exc

        raise RoleLifecycleError(
            f"Could not run role setup: {exc}{suffix}"
        ) from exc
