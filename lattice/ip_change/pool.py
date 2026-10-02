"""Master-owned automatic address pool for Lattice workers."""

from dataclasses import asdict, dataclass
import ipaddress
import json
import os
from pathlib import Path
import tempfile


DEFAULT_POOL_PATH = Path("/etc/lattice/address-pool.json")


class AddressPoolError(ValueError):
    pass


@dataclass(frozen=True)
class AddressPool:
    network: str
    start: str
    end: str
    gateway: str
    prefix: int
    dns: tuple[str, ...]
    interface: str


def _pool_path():
    return Path(os.environ.get("LATTICE_ADDRESS_POOL_PATH", DEFAULT_POOL_PATH))


def validate_pool(pool):
    try:
        network = ipaddress.IPv4Network(pool.network, strict=True)
        start = ipaddress.IPv4Address(pool.start)
        end = ipaddress.IPv4Address(pool.end)
        gateway = ipaddress.IPv4Address(pool.gateway)
    except ipaddress.AddressValueError as exc:
        raise AddressPoolError("The address pool contains an invalid IPv4 address.") from exc
    if network.prefixlen != pool.prefix:
        raise AddressPoolError("The pool prefix does not match its network.")
    if not (start in network and end in network and gateway in network):
        raise AddressPoolError("The pool and gateway must be inside the same network.")
    if int(start) > int(end):
        raise AddressPoolError("The beginning of the pool must come before its end.")
    if gateway in (network.network_address, network.broadcast_address):
        raise AddressPoolError("The gateway is a reserved network address.")
    if not pool.interface:
        raise AddressPoolError("The master network interface is missing.")
    for server in pool.dns:
        try:
            ipaddress.IPv4Address(server)
        except ipaddress.AddressValueError as exc:
            raise AddressPoolError("The pool contains an invalid DNS address.") from exc
    return pool


def suggested_pool(current_ip, prefix, gateway, interface, size=21):
    """Suggest a small high-address pool; the installer asks once for approval."""
    try:
        network = ipaddress.IPv4Network(f"{current_ip}/{prefix}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise AddressPoolError("Could not determine the local IPv4 network.") from exc
    if network.num_addresses < size + 4:
        raise AddressPoolError("This network is too small for an automatic Lattice address pool.")

    # On normal /24 home networks this proposes .200 through .220.  On a
    # smaller subnet it uses the last usable addresses instead.
    offset_start = 200
    if int(network.network_address) + offset_start + size - 1 >= int(network.broadcast_address):
        offset_start = network.num_addresses - size - 1
    start = ipaddress.IPv4Address(int(network.network_address) + offset_start)
    end = ipaddress.IPv4Address(int(start) + size - 1)
    return validate_pool(
        AddressPool(
            network=str(network),
            start=str(start),
            end=str(end),
            gateway=str(gateway),
            prefix=network.prefixlen,
            dns=(str(gateway),),
            interface=interface,
        )
    )



def find_contiguous_available_pool(
    current_ip, prefix, gateway, interface, is_in_use, *, dns=(), size=21, on_check=None
):
    """Build a pool only after a live scan proves one contiguous block unused.

    On normal /24 home networks scanning begins at .200 to preserve the
    familiar high-address preference, then wraps once through the remaining
    usable subnet if that area cannot provide a full block.
    """
    try:
        network = ipaddress.IPv4Network(f"{current_ip}/{prefix}", strict=False)
        gateway_ip = ipaddress.IPv4Address(gateway)
        current = ipaddress.IPv4Address(current_ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise AddressPoolError("Could not determine the local IPv4 network.") from exc
    if not callable(is_in_use):
        raise AddressPoolError("Address availability checker is unavailable.")
    usable = list(network.hosts())
    if len(usable) < size:
        raise AddressPoolError("This network is too small for the Lattice address pool.")

    preferred = ipaddress.IPv4Address(int(network.network_address) + 200)
    try:
        preferred_index = usable.index(preferred)
    except ValueError:
        preferred_index = max(0, len(usable) - size)
    ordered_segments = (usable[preferred_index:], usable[:preferred_index])
    reserved = {current, gateway_ip}

    for segment in ordered_segments:
        run = []
        for candidate_ip in segment:
            candidate = str(candidate_ip)
            if candidate_ip in reserved:
                run = []
                continue
            if on_check is not None:
                on_check(candidate)
            if is_in_use(candidate):
                run = []
                continue
            run.append(candidate_ip)
            if len(run) == size:
                start, end = run[0], run[-1]
                return validate_pool(AddressPool(
                    network=str(network),
                    start=str(start),
                    end=str(end),
                    gateway=str(gateway_ip),
                    prefix=network.prefixlen,
                    dns=tuple(str(ipaddress.IPv4Address(v)) for v in dns),
                    interface=interface,
                ))
    raise AddressPoolError(
        f"No contiguous block of {size} currently unused addresses was found on {network}."
    )


def choose_available_address(pool, reserved_addresses, is_in_use, on_check=None):
    """Choose the first unreserved, currently unused address in a pool.

    ``on_check`` is an optional progress callback invoked before each live
    duplicate-address probe.
    """
    validate_pool(pool)
    reserved = {str(ipaddress.IPv4Address(address)) for address in reserved_addresses}
    start = int(ipaddress.IPv4Address(pool.start))
    end = int(ipaddress.IPv4Address(pool.end))
    for value in range(start, end + 1):
        candidate = str(ipaddress.IPv4Address(value))
        if candidate == pool.gateway or candidate in reserved:
            continue
        if on_check is not None:
            on_check(candidate)
        if not is_in_use(candidate):
            return candidate
    raise AddressPoolError("No unused address is available in the Lattice address pool.")


def _atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o644)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o644)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def write_address_pool(pool):
    validate_pool(pool)
    payload = asdict(pool)
    payload["dns"] = list(pool.dns)
    _atomic_write(_pool_path(), payload)


def read_address_pool():
    path = _pool_path()
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["dns"] = tuple(payload.get("dns", ()))
        return validate_pool(AddressPool(**payload))
    except (OSError, json.JSONDecodeError, TypeError, AddressPoolError) as exc:
        raise AddressPoolError(f"The saved Lattice address pool is invalid: {exc}") from exc
