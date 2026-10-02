"""Fail-safe, one-time static IPv4 setup using NetworkManager."""

from dataclasses import asdict, dataclass
import ipaddress
import os
import re
import subprocess

from lattice.ip_change.state import (
    clear_expected_network,
    preserve_original_network_state,
    read_expected_network,
    write_expected_network,
    write_state,
)


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class StaticIPError(RuntimeError):
    """Raised when a static-IP change cannot be completed safely."""


@dataclass(frozen=True)
class StaticIPPlan:
    interface: str
    connection: str
    address: str
    prefix: int
    gateway: str
    dns: tuple = ()


def _run(command, **kwargs):
    return subprocess.run(command, **kwargs)


def prefix_from_netmask(netmask):
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise StaticIPError(f"Invalid subnet mask: {netmask}") from exc


def validate_plan(plan):
    if not _INTERFACE_RE.fullmatch(plan.interface):
        raise StaticIPError("The network interface name is invalid.")
    if not plan.connection or "\n" in plan.connection or "\x00" in plan.connection:
        raise StaticIPError("The NetworkManager connection name is invalid.")
    if not isinstance(plan.prefix, int) or not 1 <= plan.prefix <= 30:
        raise StaticIPError("The network prefix must be between 1 and 30.")

    try:
        address = ipaddress.IPv4Address(plan.address)
        gateway = ipaddress.IPv4Address(plan.gateway)
        network = ipaddress.IPv4Network(f"{address}/{plan.prefix}", strict=False)
    except ipaddress.AddressValueError as exc:
        raise StaticIPError("The planned address or gateway is not valid IPv4.") from exc

    if gateway not in network:
        raise StaticIPError("The gateway is not inside the planned network.")
    if address in (network.network_address, network.broadcast_address):
        raise StaticIPError("The planned address is reserved by the network.")
    if gateway in (network.network_address, network.broadcast_address):
        raise StaticIPError("The gateway address is reserved by the network.")
    if address == gateway:
        raise StaticIPError("The planned address cannot be the gateway address.")

    for server in plan.dns:
        try:
            ipaddress.IPv4Address(server)
        except ipaddress.AddressValueError as exc:
            raise StaticIPError(f"Invalid DNS server: {server}") from exc
    return plan


def _checked(runner, command):
    try:
        result = runner(command, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise StaticIPError(f"Could not run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise StaticIPError(f"{command[0]} failed: {detail}")
    return result


def detect_dns_servers(interface, runner=_run):
    """Return the active IPv4 DNS servers reported by NetworkManager."""
    if not _INTERFACE_RE.fullmatch(interface):
        raise StaticIPError("The network interface name is invalid.")
    result = _checked(
        runner,
        ["nmcli", "-g", "IP4.DNS", "device", "show", interface],
    )
    servers = []
    # NetworkManager output varies by version. With terse output, multiple DNS
    # values may arrive as separate lines or as one pipe-delimited line.
    # Parse both forms strictly.
    for token in result.stdout.replace("|", "\n").splitlines():
        value = token.strip()
        if not value:
            continue
        try:
            address = str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            continue
        if address not in servers:
            servers.append(address)
    if not servers:
        raise StaticIPError(
            f"NetworkManager did not report an active IPv4 DNS server for {interface}."
        )
    return tuple(servers)


def detect_connection(interface, runner=_run):
    if not _INTERFACE_RE.fullmatch(interface):
        raise StaticIPError("The network interface name is invalid.")
    result = _checked(
        runner,
        ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", interface],
    )
    connection = result.stdout.strip()
    if not connection or connection == "--":
        raise StaticIPError(f"No active NetworkManager connection exists for {interface}.")
    return connection


def snapshot_connection(connection, runner=_run):
    snapshot = {"connection": connection}
    for field in ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns"):
        result = _checked(
            runner,
            ["nmcli", "-g", field, "connection", "show", connection],
        )
        snapshot[field] = result.stdout.strip()
    return snapshot


def restore_connection(snapshot, interface, runner=_run):
    connection = snapshot["connection"]
    command = ["nmcli", "connection", "modify", connection]
    for field in ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns"):
        command.extend([field, snapshot.get(field, "")])
    _checked(runner, command)
    _checked(runner, ["nmcli", "connection", "up", connection, "ifname", interface])


def _gateway_is_reachable(interface, gateway, runner):
    try:
        result = runner(
            ["ping", "-c", "2", "-W", "2", "-I", interface, gateway],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise StaticIPError(f"Could not test the gateway: {exc}") from exc
    return result.returncode == 0


def _address_is_available(interface, address, runner):
    """Return True only when duplicate-address probing proves an IPv4 address is free.

    Ubuntu/Debian commonly ships Thomas Habets' ``arping`` where ``-i`` selects
    the interface and exit 1 means no reply (free).  iputils ``arping`` uses
    ``-I`` plus DAD mode, where exit 0 means no duplicate (free).
    """
    try:
        habets = runner(
            ["arping", "-q", "-0", "-i", interface, "-c", "2", "-w", "3", address],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise StaticIPError(f"Could not check whether the address is free: {exc}") from exc

    if habets.returncode == 0:
        return False
    if habets.returncode == 1 and not (habets.stderr or "").strip():
        return True

    # If this is the iputils implementation, Habets-specific flags are rejected.
    error_text = f"{habets.stdout or ''} {habets.stderr or ''}".lower()
    unsupported = any(token in error_text for token in (
        "invalid option", "unknown option", "unrecognized option", "illegal option", "usage:",
    ))
    if not unsupported:
        raise StaticIPError(
            "Could not check whether the address is free: "
            + ((habets.stderr or habets.stdout or "arping failed").strip())
        )

    try:
        iputils = runner(
            ["arping", "-D", "-I", interface, "-c", "2", "-w", "3", address],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise StaticIPError(f"Could not check whether the address is free: {exc}") from exc
    if iputils.returncode in (0, 1):
        return iputils.returncode == 0
    raise StaticIPError(
        "Could not check whether the address is free: "
        + ((iputils.stderr or iputils.stdout or "arping failed").strip())
    )


def is_address_available(interface, address, runner=_run):
    """Return whether duplicate-address detection finds this IPv4 address free."""
    return _address_is_available(interface, address, runner)


def _address_is_present(plan, runner):
    result = _checked(
        runner,
        ["ip", "-4", "-o", "address", "show", "dev", plan.interface],
    )
    expected = f"{plan.address}/{plan.prefix}"
    return expected in result.stdout.split()


def apply_static_ip(plan, runner=_run, require_root=True):
    """Apply and verify a plan, restoring the exact old settings on failure."""
    validate_plan(plan)
    if require_root and os.geteuid() != 0:
        raise StaticIPError("Static-IP setup must be run with administrator permission.")
    if not _gateway_is_reachable(plan.interface, plan.gateway, runner):
        raise StaticIPError("The gateway is not reachable with the current settings.")
    if not _address_is_available(plan.interface, plan.address, runner):
        raise StaticIPError("Another device appears to be using the planned address.")

    snapshot = snapshot_connection(plan.connection, runner)
    previous_expected = read_expected_network()

    # Only the very first Lattice network change is allowed to
    # establish the uninstall/restore baseline.
    if previous_expected is None:
        preserve_original_network_state(
            {
                "interface": plan.interface,
                "snapshot": snapshot,
            }
        )

    transaction = {
        "status": "prepared",
        "interface": plan.interface,
        "plan": asdict(plan),
        "snapshot": snapshot,
        "previous_expected": previous_expected,
    }
    write_state(transaction)

    try:
        transaction["status"] = "applying"
        write_state(transaction)
        dns_value = ",".join(plan.dns)
        _checked(
            runner,
            [
                "nmcli", "connection", "modify", plan.connection,
                "ipv4.method", "manual",
                "ipv4.addresses", f"{plan.address}/{plan.prefix}",
                "ipv4.gateway", plan.gateway,
                "ipv4.dns", dns_value,
            ],
        )
        _checked(
            runner,
            ["nmcli", "connection", "up", plan.connection, "ifname", plan.interface],
        )

        transaction["status"] = "verifying"
        write_state(transaction)
        if not _address_is_present(plan, runner):
            raise StaticIPError("The planned address did not become active.")
        if not _gateway_is_reachable(plan.interface, plan.gateway, runner):
            raise StaticIPError("The gateway became unreachable after the change.")

        expected = asdict(plan)
        expected["dns"] = list(plan.dns)
        write_expected_network(expected)
        transaction["status"] = "committed"
        write_state(transaction)
    except Exception as exc:
        transaction["status"] = "reverting"
        transaction["error"] = str(exc)
        try:
            write_state(transaction)
        except Exception:
            # A state-file problem must never prevent the network rollback.
            pass
        try:
            restore_connection(snapshot, plan.interface, runner)
        except Exception as rollback_exc:
            transaction["status"] = "rollback_failed"
            transaction["rollback_error"] = str(rollback_exc)
            write_state(transaction)
            raise StaticIPError(
                f"The network change failed and automatic restore also failed: {rollback_exc}"
            ) from exc
        previous_expected = transaction.get("previous_expected")
        if previous_expected is None:
            clear_expected_network()
        else:
            write_expected_network(previous_expected)
        transaction["status"] = "reverted"
        write_state(transaction)
        if isinstance(exc, StaticIPError):
            raise
        raise StaticIPError(f"The network change failed and was restored: {exc}") from exc

    return expected
