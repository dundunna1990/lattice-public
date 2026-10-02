"""First-time-only firewall preparation for Lattice access on the local LAN."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
import shutil
import subprocess
import json
import tempfile
from pathlib import Path

import netifaces

FIREWALL_MANIFEST = Path("/etc/lattice/firewall-rules.json")


class SSHFirewallError(RuntimeError):
    """Raised when SSH cannot be made reachable without unsafe firewall changes."""


@dataclass(frozen=True)
class SSHFirewallResult:
    firewall: str
    subnet: str
    changed: bool
    added_rules: tuple = ()


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def detect_local_subnet():
    try:
        gateway = netifaces.gateways()["default"][netifaces.AF_INET]
        interface = gateway[1]
        address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        return str(ipaddress.IPv4Network(f"{address['addr']}/{address['netmask']}", strict=False))
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise SSHFirewallError("Could not determine this computer's local IPv4 network.") from exc


def _is_active_ufw(runner):
    result = runner(["ufw", "status"])
    if result.returncode != 0:
        raise SSHFirewallError(f"Could not read UFW status: {(result.stderr or result.stdout).strip()}")
    return "Status: active" in result.stdout


def _required_ports(api_port: int) -> tuple[int, ...]:
    if isinstance(api_port, bool) or not isinstance(api_port, int) or not 1 <= api_port <= 65535:
        raise SSHFirewallError("The role API port must be an integer from 1 through 65535.")
    # Open only Lattice's LAN-facing channels: recovery SSH, file transport,
    # trusted shell, dedicated Backup SFTP, and the selected role API.
    return tuple(dict.fromkeys((22, 22022, 22023, 22024, api_port)))


def _ufw_rule(subnet: str, port: int) -> list[str]:
    return [
        "ufw", "allow", "from", subnet, "to", "any",
        "port", str(port), "proto", "tcp", "comment", "Lattice local LAN",
    ]


def _rollback_ufw(subnet: str, ports: list[int], runner) -> None:
    for port in reversed(ports):
        runner([
            "ufw", "--force", "delete", "allow", "from", subnet, "to", "any",
            "port", str(port), "proto", "tcp", "comment", "Lattice local LAN",
        ])


def _ufw_default_input_is_restrictive(path: Path = Path("/etc/default/ufw")) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SSHFirewallError(f"Could not read UFW defaults: {exc}") from exc
    for line in text.splitlines():
        if line.startswith("DEFAULT_INPUT_POLICY="):
            value = line.split("=", 1)[1].strip().strip('\"').upper()
            return value in {"DROP", "REJECT"}
    return False


def enable_inactive_ufw_for_lattice(
    *, api_port: int, runner=_run, finder=shutil.which,
    subnet_detector=detect_local_subnet, require_root=True,
    defaults_path: Path = Path("/etc/default/ufw"),
):
    """Stage LAN-only Lattice rules, then enable inactive UFW and verify it.

    Existing UFW rules are preserved. Only rules added by this operation are
    rolled back on failure, and UFW is disabled again if Lattice enabled it.
    """
    if require_root and os.geteuid() != 0:
        raise SSHFirewallError("UFW activation requires administrator access.")
    if not finder("ufw"):
        raise SSHFirewallError("UFW is not installed.")
    ports = _required_ports(api_port)
    try:
        subnet = str(ipaddress.IPv4Network(subnet_detector(), strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError, ValueError) as exc:
        raise SSHFirewallError("The detected local IPv4 network is invalid.") from exc
    if _is_active_ufw(runner):
        return _configure_ufw(subnet, ports, runner)
    if not _ufw_default_input_is_restrictive(defaults_path):
        raise SSHFirewallError(
            "UFW's default incoming policy is not DROP/REJECT; Lattice will not enable it automatically."
        )
    added: list[int] = []
    enabled_by_us = False
    try:
        for port in ports:
            result = runner(_ufw_rule(subnet, port))
            if result.returncode != 0:
                raise SSHFirewallError(
                    f"Could not stage required local-LAN TCP/{port} through UFW: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
            output = (result.stdout + result.stderr).lower()
            if "skipping" not in output and "existing rule" not in output:
                added.append(port)
        enabled = runner(["ufw", "--force", "enable"])
        if enabled.returncode != 0:
            raise SSHFirewallError(
                f"Could not enable UFW: {(enabled.stderr or enabled.stdout).strip()}"
            )
        enabled_by_us = True
        verification = runner(["ufw", "status"] )
        if verification.returncode != 0 or "Status: active" not in verification.stdout:
            raise SSHFirewallError("UFW did not report active after enablement.")
        verified_ports = {
            port for port in ports
            if any(f"{port}/tcp" in line and subnet in line for line in verification.stdout.splitlines())
        }
        if verified_ports != set(ports):
            raise SSHFirewallError("UFW did not show every required local-LAN TCP rule after enablement.")
    except Exception:
        if enabled_by_us:
            runner(["ufw", "disable"])
        _rollback_ufw(subnet, added, runner)
        raise
    if require_root and added:
        _write_firewall_manifest({
            "firewall": "ufw", "subnet": subnet,
            "rules": [{"port": port} for port in added],
            "enabled_by_lattice": True,
        })
    return SSHFirewallResult("ufw", subnet, True, tuple(added))


def _configure_ufw(subnet, ports, runner):
    if not _is_active_ufw(runner):
        return SSHFirewallResult("ufw (inactive)", subnet, False)
    added: list[int] = []
    for port in ports:
        result = runner(_ufw_rule(subnet, port))
        if result.returncode != 0:
            _rollback_ufw(subnet, added, runner)
            raise SSHFirewallError(
                f"Could not allow required local-LAN TCP/{port} through UFW: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        output = (result.stdout + result.stderr).lower()
        if "skipping" not in output and "existing rule" not in output:
            added.append(port)
    verification = runner(["ufw", "status"])
    verified_ports = {
        port
        for port in ports
        if any(
            f"{port}/tcp" in line and subnet in line
            for line in verification.stdout.splitlines()
        )
    }
    if verification.returncode != 0 or verified_ports != set(ports):
        _rollback_ufw(subnet, added, runner)
        raise SSHFirewallError("UFW did not show every required local-LAN TCP rule after setup.")
    return SSHFirewallResult("ufw", subnet, bool(added), tuple(added))


def _active_firewalld_zone(runner):
    result = runner(["firewall-cmd", "--get-active-zones"])
    if result.returncode != 0:
        raise SSHFirewallError(f"Could not read firewalld zones: {(result.stderr or result.stdout).strip()}")
    for line in result.stdout.splitlines():
        value = line.strip()
        if value and not value.startswith("interfaces:") and not value.startswith("sources:"):
            return value
    default = runner(["firewall-cmd", "--get-default-zone"])
    if default.returncode == 0 and default.stdout.strip():
        return default.stdout.strip()
    raise SSHFirewallError("Could not find the active firewalld zone.")


def _firewalld_rule(subnet: str, port: int) -> str:
    return (
        f'rule family="ipv4" source address="{subnet}" '
        f'port port="{port}" protocol="tcp" accept'
    )


def _rollback_firewalld(zone, runtime_rules, permanent_rules, runner):
    for rule in reversed(runtime_rules):
        runner(["firewall-cmd", "--zone", zone, "--remove-rich-rule", rule])
    for rule in reversed(permanent_rules):
        runner(["firewall-cmd", "--permanent", "--zone", zone, "--remove-rich-rule", rule])


def _configure_firewalld(subnet, ports, runner):
    state = runner(["firewall-cmd", "--state"])
    if state.returncode != 0 or state.stdout.strip() != "running":
        return SSHFirewallResult("firewalld (inactive)", subnet, False)
    zone = _active_firewalld_zone(runner)
    permanent_added: list[str] = []
    runtime_added: list[str] = []
    rules = [_firewalld_rule(subnet, port) for port in ports]
    added_records = []
    for port, rule in zip(ports, rules):
        permanent = runner(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", rule])
        permanent_output = permanent.stderr + permanent.stdout
        permanent_exists = "ALREADY_ENABLED" in permanent_output
        if permanent.returncode != 0 and not permanent_exists:
            _rollback_firewalld(zone, runtime_added, permanent_added, runner)
            raise SSHFirewallError(
                f"Could not save the local-LAN TCP/{port} firewalld rule: "
                f"{(permanent.stderr or permanent.stdout).strip()}"
            )
        if not permanent_exists:
            permanent_added.append(rule)

        runtime = runner(["firewall-cmd", "--zone", zone, "--add-rich-rule", rule])
        runtime_output = runtime.stderr + runtime.stdout
        runtime_exists = "ALREADY_ENABLED" in runtime_output
        if runtime.returncode != 0 and not runtime_exists:
            _rollback_firewalld(zone, runtime_added, permanent_added, runner)
            raise SSHFirewallError(
                f"Could not activate the local-LAN TCP/{port} firewalld rule: "
                f"{(runtime.stderr or runtime.stdout).strip()}"
            )
        if not runtime_exists:
            runtime_added.append(rule)
        if not runtime_exists or not permanent_exists:
            added_records.append((port, not runtime_exists, not permanent_exists))
    verification = runner(["firewall-cmd", "--zone", zone, "--list-rich-rules"])
    if verification.returncode != 0 or any(rule not in verification.stdout for rule in rules):
        _rollback_firewalld(zone, runtime_added, permanent_added, runner)
        raise SSHFirewallError("firewalld did not show every required local-LAN TCP rule after setup.")
    return SSHFirewallResult(
        "firewalld", subnet, bool(runtime_added or permanent_added), tuple(added_records)
    )


def _refuse_unsupported_active_firewall(runner, finder):
    if finder("nft"):
        result = runner(["nft", "list", "ruleset"])
        if result.returncode == 0 and result.stdout.strip():
            raise SSHFirewallError(
                "An active nftables firewall was found. Lattice will not guess or disable it; add local-LAN SSH and role API rules first."
            )
    if finder("iptables"):
        result = runner(["iptables", "-S"])
        if result.returncode == 0 and "-P INPUT DROP" in result.stdout:
            raise SSHFirewallError(
                "An active iptables firewall was found. Lattice will not guess or disable it; add local-LAN SSH and role API rules first."
            )


def ensure_local_lan_ssh_firewall(
    *,
    api_port: int,
    runner=_run,
    finder=shutil.which,
    subnet_detector=detect_local_subnet,
    require_root=True,
):
    """Allow Lattice SSH channels and the selected role's API only from the local subnet.

    This never enables or disables a firewall, never opens a port to the
    internet, and is intentionally called only by the installation wizard.
    """
    if require_root and os.geteuid() != 0:
        raise SSHFirewallError("SSH firewall setup requires administrator access.")
    ports = _required_ports(api_port)
    try:
        subnet = str(ipaddress.IPv4Network(subnet_detector(), strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError, ValueError) as exc:
        raise SSHFirewallError("The detected local IPv4 network is invalid.") from exc
    inactive_ufw = None
    if finder("ufw"):
        inactive_ufw = _configure_ufw(subnet, ports, runner)
        if inactive_ufw.firewall == "ufw":
            if require_root and inactive_ufw.changed:
                _write_firewall_manifest({
                    "firewall": "ufw",
                    "subnet": subnet,
                    "rules": [{"port": port} for port in inactive_ufw.added_rules],
                })
            return inactive_ufw
    if finder("firewall-cmd"):
        result = _configure_firewalld(subnet, ports, runner)
        if require_root and result.changed:
            zone = _active_firewalld_zone(runner)
            _write_firewall_manifest({
                "firewall": "firewalld",
                "subnet": subnet,
                "zone": zone,
                "rules": [
                    {"port": port, "runtime": runtime, "permanent": permanent}
                    for port, runtime, permanent in result.added_rules
                ],
            })
        return result
    if inactive_ufw is not None:
        return inactive_ufw
    _refuse_unsupported_active_firewall(runner, finder)
    return SSHFirewallResult("no supported active firewall", subnet, False)


def _write_firewall_manifest(payload: dict) -> None:
    FIREWALL_MANIFEST.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(
        dir=FIREWALL_MANIFEST.parent, prefix=f".{FIREWALL_MANIFEST.name}."
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, FIREWALL_MANIFEST)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def remove_lattice_firewall_rules(runner=_run) -> bool:
    """Remove only rules recorded by Lattice during guided setup."""
    try:
        metadata = FIREWALL_MANIFEST.lstat()
    except FileNotFoundError:
        return False
    if not FIREWALL_MANIFEST.is_file() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise SSHFirewallError("The Lattice firewall manifest is unsafe; no firewall changes were made")
    payload = json.loads(FIREWALL_MANIFEST.read_text(encoding="utf-8"))
    subnet = str(ipaddress.IPv4Network(payload["subnet"], strict=True))
    records = payload.get("rules", [])
    if not isinstance(records, list) or not records or len(records) > 16:
        raise SSHFirewallError("The Lattice firewall manifest contains an invalid rule list")
    ports = []
    for record in records:
        if not isinstance(record, dict):
            raise SSHFirewallError("The Lattice firewall manifest contains an invalid rule")
        port = int(record.get("port", 0))
        if not 1 <= port <= 65535:
            raise SSHFirewallError("The Lattice firewall manifest contains an invalid port")
        ports.append(port)
    if payload.get("firewall") == "ufw":
        for port in ports:
            result = runner([
                "ufw", "--force", "delete", "allow", "from", subnet, "to", "any",
                "port", str(port), "proto", "tcp", "comment", "Lattice local LAN",
            ])
            if result.returncode != 0:
                raise SSHFirewallError(f"Could not remove recorded Lattice UFW rule for TCP/{port}")
        if payload.get("enabled_by_lattice") is True:
            result = runner(["ufw", "disable"])
            if result.returncode != 0:
                raise SSHFirewallError("Could not restore UFW to its pre-Lattice inactive state")
    elif payload.get("firewall") == "firewalld":
        zone = payload.get("zone")
        if not isinstance(zone, str) or not zone:
            raise SSHFirewallError("The Lattice firewalld zone record is invalid")
        for port, record in zip(ports, records):
            rule = _firewalld_rule(subnet, port)
            prefixes = []
            if record.get("runtime") is True:
                prefixes.append(["firewall-cmd", "--zone", zone])
            if record.get("permanent") is True:
                prefixes.append(["firewall-cmd", "--permanent", "--zone", zone])
            if not prefixes:
                raise SSHFirewallError("The Lattice firewalld rule record is invalid")
            for prefix in prefixes:
                result = runner([*prefix, "--remove-rich-rule", rule])
                if result.returncode != 0:
                    raise SSHFirewallError(f"Could not remove recorded Lattice firewalld rule for TCP/{port}")
    else:
        raise SSHFirewallError("The Lattice firewall manifest names an unsupported firewall")
    FIREWALL_MANIFEST.unlink()
    return True


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--remove-lattice-rules"] or os.geteuid() != 0:
        raise SystemExit("Usage: sudo python -m lattice.core.ssh_firewall --remove-lattice-rules")
    remove_lattice_firewall_rules()
