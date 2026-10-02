import logging
logger = logging.getLogger(__name__)

"""
mDNS discovery for Lattice workers – XML service file approach.
Uses system Avahi daemon; no Python zeroconf.
"""

import os
import re
import subprocess
import fcntl
import time
import json
import shlex
from pathlib import Path
from typing import List, Dict, Any, Optional

SERVICE_TYPE = "_lattice._tcp"
DEFAULT_PORT = 9999
SERVICE_FILE = "/etc/avahi/services/lattice.service"
LOCK_FILE = f"/run/user/{os.getuid()}/lattice-broadcast.lock"
AVAHI_DROPDIR = "/etc/systemd/resolved.conf.d"
AVAHI_DROPIN = "99-lattice-mdns.conf"


def _acquire_lock() -> Optional[int]:
    try:
        os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
        # Check for stale lock file
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, 'r') as f:
                    old_pid = int(f.read().strip())
                os.kill(old_pid, 0)
                return None
            except (ProcessLookupError, ValueError, FileNotFoundError):
                try:
                    os.unlink(LOCK_FILE)
                except OSError:
                    pass
        fd = os.open(LOCK_FILE, os.O_WRONLY | os.O_CREAT, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, f"{os.getpid()}\n".encode())
        return fd
    except (BlockingIOError, OSError):
        return None

def _release_lock(fd: int):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        os.unlink(LOCK_FILE)
    except Exception:
        pass


def write_service_file(instance: str, port: int = DEFAULT_PORT, txt: Optional[Dict] = None) -> None:
    txt_records = ""
    if txt:
        for k, v in txt.items():
            txt_records += '    <txt-record>{0}={1}</txt-record>\n'.format(k, v)
    xml = """<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">Lattice Worker on %h</name>
  <service>
    <type>{0}</type>
    <port>{1}</port>
    {2}
  </service>
</service-group>
""".format(SERVICE_TYPE, port, txt_records)
    os.makedirs(os.path.dirname(SERVICE_FILE), exist_ok=True)
    # Atomic write: write to .tmp, fsync, rename. If interrupted mid-write,
    # the original SERVICE_FILE is untouched.
    import tempfile as _mdns_tempfile
    _dir = os.path.dirname(SERVICE_FILE)
    _fd, _tmp = _mdns_tempfile.mkstemp(dir=_dir, prefix=".lattice-svc.", suffix=".tmp")
    try:
        with os.fdopen(_fd, 'w') as _f:
            _f.write(xml)
            _f.flush()
            os.fsync(_f.fileno())
            # mkstemp() intentionally creates the temporary file as 0600.
            # Avahi reads service definitions as an unprivileged daemon, so the
            # final service file must be world-readable while remaining root-owned.
            os.fchmod(_f.fileno(), 0o644)
        os.replace(_tmp, SERVICE_FILE)
    except Exception:
        try:
            os.unlink(_tmp)
        except OSError:
            pass
        raise


def remove_service_file() -> None:
    if os.path.exists(SERVICE_FILE):
        os.unlink(SERVICE_FILE)


def publish_service(instance: str, port: int = DEFAULT_PORT, txt: Optional[Dict] = None, ssh_user: Optional[str] = None) -> bool:
    try:
        subprocess.run(["systemctl", "is-active", "--quiet", "avahi-daemon"], check=True, timeout=30,)
    except subprocess.CalledProcessError:
        raise RuntimeError("avahi-daemon is not running. Start it with: sudo systemctl start avahi-daemon")

    lock_fd = _acquire_lock()
    if lock_fd is None:
        raise RuntimeError("Lattice broadcaster already running")

    if txt is None:
        txt = {}
    if ssh_user:
        txt['ssh_user'] = ssh_user

    write_service_file(instance, port, txt)
    return True


def publish_waiting_worker(pairing_id: str, hostname: str, ssh_user: str, port: int = DEFAULT_PORT) -> bool:
    """Publish a worker that is waiting for a master to pair it.

    The pairing code is intentionally absent from mDNS records. A discovered
    worker is only a candidate; the code shown on its own screen is still
    required before it can accept a master.
    """
    return publish_service(
        instance=f"Lattice Worker {hostname} (waiting)",
        port=port,
        txt={
            "role": "worker",
            "state": "waiting",
            "pairing_id": pairing_id,
            "hostname": hostname,
        },
    )


def stop_broadcast() -> bool:
    remove_service_file()
    try:
        fd = os.open(LOCK_FILE, os.O_RDONLY)
        pid = int(os.read(fd, 64).decode().strip())
        if pid == os.getpid():
            _release_lock(fd)
        else:
            os.close(fd)
            os.unlink(LOCK_FILE)
    except Exception:
        logger.warning("Failed to stop broadcast")
        pass
    return True


def _is_reachable(addr: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP connect to verify the host is actually up.
    Used to filter out stale mDNS cache entries.
    """
    import socket as _socket
    try:
        sock = _socket.create_connection((addr, port), timeout=timeout)
        sock.close()
        return True
    except (OSError, _socket.timeout):
        return False


def _detect_local_subnet() -> Optional[str]:
    """Best-effort: find the local subnet in CIDR notation."""
    try:
        import netifaces as _netifaces
        gateways = _netifaces.gateways()
        default = gateways.get("default", {}).get(_netifaces.AF_INET)
        if not default:
            return None
        iface = default[1]
        addrs = _netifaces.ifaddresses(iface)
        if _netifaces.AF_INET not in addrs or not addrs[_netifaces.AF_INET]:
            return None
        ip_str = addrs[_netifaces.AF_INET][0].get("addr")
        netmask = addrs[_netifaces.AF_INET][0].get("netmask", "255.255.255.0")
        if not ip_str or not netmask:
            return None
        import ipaddress as _ip
        return str(_ip.ip_network(f"{ip_str}/{netmask}", strict=False))
    except Exception:
        return None


def _quick_ping_sweep(subnet: str, timeout: float = 1.0) -> List[str]:
    """Parallel ping sweep fallback. Returns list of responsive IPs."""
    import ipaddress as _ip
    import concurrent.futures as _cf
    try:
        net = _ip.ip_network(subnet, strict=False)
    except ValueError:
        return []
    hosts = [str(h) for h in net.hosts()]

    def _ping(ip: str) -> Optional[str]:
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=2
            )
            return ip if r.returncode == 0 else None
        except Exception:
            return None

    found: list[str] = []
    with _cf.ThreadPoolExecutor(max_workers=32) as ex:
        for result in ex.map(_ping, hosts):
            if result:
                found.append(result)
    return found


def discover_workers(timeout: float = 3) -> List[Dict[str, Any]]:
    """Discover workers via mDNS, verify reachability, fall back to ping sweep.

    Bulletproofness:
    - Filters out stale mDNS cache entries via quick TCP connect.
    - If mDNS returns nothing, falls back to a parallel ping sweep of the
      local subnet. (Handles the case where Avahi is down or the network
      blip took out the mDNS responder.)
    - All timeouts bounded so this function never blocks more than
      timeout + 10s.
    """
    cmd = ["avahi-browse", "-rkpt", "--", SERVICE_TYPE]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        workers = _parse_avahi_output(result.stdout)
    except FileNotFoundError:
        raise RuntimeError("avahi-browse not found. Install: sudo apt install avahi-utils")
    except subprocess.TimeoutExpired:
        workers = []
    except Exception as e:
        logger.warning(f"avahi-browse failed: {e}")
        workers = []

    # Verify reachability — drop stale entries (mDNS cache can lag reality)
    verified = []
    for w in workers:
        addr = w.get("addr")
        port = int(w.get("port", DEFAULT_PORT))
        if not addr:
            continue
        if _is_reachable(addr, port, timeout=1.5):
            verified.append(w)
        else:
            logger.debug(f"Dropping stale mDNS entry {addr} (not reachable on port {port})")

    # If mDNS gave us nothing (or all entries were stale), fall back to ping sweep
    if not verified:
        subnet = _detect_local_subnet()
        if subnet:
            logger.info(f"mDNS returned no live workers; falling back to ping sweep of {subnet}")
            for ip in _quick_ping_sweep(subnet):
                if _is_reachable(ip, DEFAULT_PORT, timeout=1.0):
                    verified.append({
                        "iface": "?",
                        "proto": "IPv4",
                        "host": ip,
                        "addr": ip,
                        "port": DEFAULT_PORT,
                        "txt": {},
                    })
    return verified


def discover_waiting_workers(timeout: float = 3) -> List[Dict[str, Any]]:
    """Return only explicit, currently waiting Lattice workers.

    A ping reply is not proof that a machine belongs to Lattice, so this
    intentionally does not use the generic ping-sweep fallback.
    """
    cmd = ["avahi-browse", "-rkpt", "--", SERVICE_TYPE]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        workers = _parse_avahi_output(result.stdout)
    except FileNotFoundError as exc:
        raise RuntimeError("avahi-browse not found. Install avahi-utils first") from exc
    except subprocess.TimeoutExpired:
        return []

    waiting = []
    for worker in workers:
        txt = worker.get("txt", {})
        if txt.get("role") != "worker" or txt.get("state") != "waiting":
            continue
        if not txt.get("pairing_id") or not worker.get("addr"):
            continue
        if _is_reachable(worker["addr"], int(worker.get("port", DEFAULT_PORT)), timeout=1.5):
            waiting.append(worker)
    return waiting


def _parse_avahi_output(output: str) -> List[Dict[str, Any]]:
    workers = {}
    for line in output.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 10:
            continue
        _, iface, proto, name, stype, domain, host, addr, port, txt = parts[:10]
        if stype != SERVICE_TYPE or not addr or not port:
            continue
        if iface.startswith("docker") or iface.startswith("veth") or iface == "lo":
            continue
        if proto == "IPv6" and addr.startswith("fe80:"):
            continue

        txt_dict = {}
        if txt:
            import shlex
            try:
                tokens = shlex.split(txt)
            except ValueError:
                tokens = txt.split()
            for token in tokens:
                if '=' in token:
                    k, v = token.split('=', 1)
                    k = k.strip('"')
                    v = v.strip('"')
                    txt_dict[k] = v
        display_name = name
        if display_name in workers and workers[display_name]["proto"] == "IPv4":
            continue
        workers[display_name] = {
            "iface": iface,
            "proto": proto,
            "host": host,
            "addr": addr,
            "port": int(port),
            "txt": txt_dict,
        }
    return list(workers.values())


def preflight() -> None:
    try:
        subprocess.run(["avahi-browse", "--version"], capture_output=True, check=True, timeout=15,)
    except FileNotFoundError:
        print("Installing avahi-utils...")
        subprocess.run(["sudo", "-n", "apt", "install", "-y", "avahi-daemon", "avahi-utils"], check=True, timeout=10,)

    subprocess.run(["sudo", "-n", "systemctl", "enable", "--now", "avahi-daemon"], check=True, timeout=30,)

    ss = subprocess.run(["ss", "-ulnp", "sport", "= :5353"], capture_output=True, text=True, timeout=30,)
    if "avahi" not in ss.stdout:
        print("Warning: port 5353 may be blocked or used by another service")
    else:
        print("mDNS preflight passed.")
