"""Safe, local-only SSH preparation for first-time Lattice setup."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Callable


DEFAULT_CONFIG_PATH = Path("/etc/ssh/sshd_config")
DEFAULT_BACKUP_DIR = Path("/etc/lattice/backups/ssh")


class SSHSetupError(RuntimeError):
    """Raised when SSH cannot be prepared and verified safely."""


@dataclass(frozen=True)
class SSHSetupResult:
    service_name: str
    backup_path: str | None
    active: bool
    enabled: bool
    was_active: bool = False
    was_enabled: bool = False
    config_path: str = str(DEFAULT_CONFIG_PATH)


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def _loaded_service(runner: Callable[[list[str]], subprocess.CompletedProcess]) -> str:
    for service in ("ssh", "sshd"):
        result = runner(["systemctl", "show", service, "--property=LoadState", "--value"])
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            return service
    raise SSHSetupError("OpenSSH server is not installed or no SSH systemd service was found")


def _validate_sshd_config(runner: Callable[[list[str]], subprocess.CompletedProcess]) -> None:
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    result = runner([sshd, "-t"])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown validation error").strip()
        raise SSHSetupError(f"SSH configuration is invalid: {detail}")


def _is_local_ssh_listening() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 22), timeout=2):
            return True
    except OSError:
        return False


def _backup_config(config_path: Path, backup_dir: Path) -> Path | None:
    if not config_path.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"sshd_config.{stamp}.bak"
    shutil.copy2(config_path, backup_path)
    os.chmod(backup_path, 0o600)
    return backup_path


def prepare_local_ssh(
    *,
    config_path: Path = DEFAULT_CONFIG_PATH,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
    runner: Callable[[list[str]], subprocess.CompletedProcess] = _run,
    listening_check: Callable[[], bool] = _is_local_ssh_listening,
    require_root: bool = True,
) -> SSHSetupResult:
    """Validate, enable, start, and verify the local SSH server.

    This does not disable password login or rewrite sshd settings. If setup
    fails after changing the service state, it restores the previous active
    and enabled states and restores the backed-up main configuration file.
    """
    if require_root and os.geteuid() != 0:
        raise SSHSetupError("SSH preparation requires administrator access; run `sudo lattice init`")

    service = _loaded_service(runner)
    was_active = runner(["systemctl", "is-active", "--quiet", service]).returncode == 0
    was_enabled = runner(["systemctl", "is-enabled", "--quiet", service]).returncode == 0
    backup_path = _backup_config(config_path, backup_dir)

    try:
        _validate_sshd_config(runner)
        enabled = runner(["systemctl", "enable", "--now", service])
        if enabled.returncode != 0:
            detail = (enabled.stderr or enabled.stdout or "unknown systemctl error").strip()
            raise SSHSetupError(f"Could not enable and start SSH: {detail}")
        _validate_sshd_config(runner)
        if runner(["systemctl", "is-active", "--quiet", service]).returncode != 0:
            raise SSHSetupError("SSH did not remain active after setup")
        if runner(["systemctl", "is-enabled", "--quiet", service]).returncode != 0:
            raise SSHSetupError("SSH was not enabled to start after reboot")
        if not listening_check():
            raise SSHSetupError("SSH is active but is not accepting local connections on port 22")
    except Exception:
        if backup_path is not None:
            shutil.copy2(backup_path, config_path)
        if not was_active:
            runner(["systemctl", "stop", service])
        if not was_enabled:
            runner(["systemctl", "disable", service])
        raise

    return SSHSetupResult(
        service_name=service,
        backup_path=str(backup_path) if backup_path else None,
        active=True,
        enabled=True,
        was_active=was_active,
        was_enabled=was_enabled,
        config_path=str(config_path),
    )


def restore_local_ssh(result: SSHSetupResult, *, runner=_run) -> None:
    """Restore the SSH service state captured before first-time setup."""
    if result.backup_path:
        backup = Path(result.backup_path)
        if backup.is_file():
            target = Path(result.config_path)
            shutil.copy2(backup, target)
            _validate_sshd_config(runner)
    if result.was_enabled:
        action = ["systemctl", "enable", result.service_name]
    else:
        action = ["systemctl", "disable", result.service_name]
    state = runner(action, capture_output=True, text=True, timeout=30)
    if state.returncode != 0:
        detail = (state.stderr or state.stdout or "systemctl error").strip()
        raise SSHSetupError(f"Could not restore SSH enablement state: {detail}")
    desired = "start" if result.was_active else "stop"
    state = runner(
        ["systemctl", desired, result.service_name],
        capture_output=True, text=True, timeout=30,
    )
    if state.returncode != 0:
        detail = (state.stderr or state.stdout or "systemctl error").strip()
        raise SSHSetupError(f"Could not restore SSH active state: {detail}")
