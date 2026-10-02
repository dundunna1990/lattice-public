"""Version-one platform support boundary."""
from pathlib import Path
import shutil


class UnsupportedPlatformError(RuntimeError):
    pass


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def require_supported_platform(path: Path = Path("/etc/os-release")) -> None:
    try:
        values = _os_release(path)
    except OSError as exc:
        raise UnsupportedPlatformError("Lattice could not identify this operating system") from exc
    identity = values.get("ID", "").lower()
    if identity not in {"ubuntu", "linuxmint"}:
        raise UnsupportedPlatformError(
            "Lattice version 1 supports only Ubuntu or Linux Mint"
        )
    if shutil.which("nmcli") is None:
        raise UnsupportedPlatformError(
            "Lattice version 1 requires NetworkManager (the nmcli command is missing)"
        )
