"""Private-LAN route discovery and validation.

Routes are locator hints only. Lattice never treats an IP address as a
computer identity; SSH still proves the signed Node-ID host key.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import time
from typing import Iterable

_ROUTE_CACHE: tuple[float, list[dict]] | None = None
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_LOCAL_ONLY_INTERFACE_PREFIXES = (
    "docker",
    "veth",
    "virbr",
    "br-",
    "podman",
    "cni",
    "flannel",
    "lxc",
    "lxdbr",
)


class LanRouteError(ValueError):
    pass


def is_local_only_virtual_interface(interface: object) -> bool:
    name = str(interface or "").casefold()
    return any(name.startswith(prefix) for prefix in _LOCAL_ONLY_INTERFACE_PREFIXES)


def normalize_private_ipv4(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise LanRouteError("LAN route address is invalid") from exc
    if address.version != 4 or not any(address in net for net in _PRIVATE_V4):
        raise LanRouteError("LAN route must be a private IPv4 address")
    return str(address)


def _kind(interface: str) -> tuple[str, int]:
    name = interface.casefold()
    if name.startswith(("en", "eth")):
        return "ethernet", 10
    if name.startswith(("wl", "wifi", "wlan")):
        return "wifi", 20
    return "unknown", 30


def normalize_reported_routes(
    payload: object,
    *,
    maximum: int = 16,
    allow_unknown: bool = True,
) -> list[dict]:
    if payload is None:
        return []
    if not isinstance(payload, list) or len(payload) > maximum:
        raise LanRouteError("LAN routes must be a bounded list")
    result: list[dict] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise LanRouteError("LAN route must be an object")
        ip = normalize_private_ipv4(raw.get("ip"))
        interface = str(raw.get("interface", ""))
        if interface and not _INTERFACE_RE.fullmatch(interface):
            raise LanRouteError("LAN route interface name is invalid")
        if is_local_only_virtual_interface(interface):
            continue
        route_kind = raw.get("kind", "unknown")
        if route_kind not in {"ethernet", "wifi", "unknown"}:
            raise LanRouteError("LAN route kind is invalid")
        if route_kind == "unknown" and not allow_unknown:
            continue
        priority = raw.get("priority", 50)
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise LanRouteError("LAN route priority is invalid")
        if not 0 <= priority <= 1000:
            raise LanRouteError("LAN route priority is invalid")
        if ip in seen:
            continue
        seen.add(ip)
        result.append({
            "ip": ip,
            "interface": interface,
            "kind": route_kind,
            "priority": priority,
        })
    result.sort(key=lambda item: (item["priority"], item["ip"]))
    return result

def local_lan_routes(*, cache_seconds: float = 30.0) -> list[dict]:
    global _ROUTE_CACHE
    now = time.monotonic()
    if _ROUTE_CACHE is not None and now - _ROUTE_CACHE[0] < cache_seconds:
        return [dict(item) for item in _ROUTE_CACHE[1]]
    binary = shutil.which("ip")
    if not binary:
        return []
    try:
        completed = subprocess.run(
            [binary, "-j", "-4", "addr", "show", "up"],
            capture_output=True,
            text=True,
            timeout=0.5,
            check=False,
        )
        raw = json.loads(completed.stdout) if completed.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        if _ROUTE_CACHE is not None:
            return [dict(item) for item in _ROUTE_CACHE[1]]
        raw = []
    routes: list[dict] = []
    seen: set[str] = set()
    if isinstance(raw, list):
        for link in raw:
            if not isinstance(link, dict):
                continue
            interface = str(link.get("ifname", ""))
            if not interface or interface == "lo":
                continue
            if not _INTERFACE_RE.fullmatch(interface):
                continue
            if is_local_only_virtual_interface(interface):
                continue
            kind, priority = _kind(interface)
            if kind == "unknown":
                continue
            for address in link.get("addr_info", []):
                if not isinstance(address, dict):
                    continue
                if address.get("family") != "inet":
                    continue
                try:
                    ip = normalize_private_ipv4(address.get("local"))
                except LanRouteError:
                    continue
                if ip in seen:
                    continue
                seen.add(ip)
                routes.append({
                    "ip": ip,
                    "interface": interface,
                    "kind": kind,
                    "priority": priority,
                })
    routes.sort(key=lambda item: (item["priority"], item["ip"]))
    _ROUTE_CACHE = (now, routes)
    return [dict(item) for item in routes]

def discovered_hostname_ips(hostname: str) -> list[str]:
    """Best-effort LAN DNS/mDNS discovery; returned IPs are never trusted alone."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", hostname):
        return []
    binary = shutil.which("getent")
    if not binary:
        return []
    found: list[str] = []
    for candidate in (hostname, f"{hostname}.local"):
        try:
            completed = subprocess.run(
                [binary, "ahostsv4", candidate],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            continue
        for line in completed.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            try:
                ip = normalize_private_ipv4(fields[0])
            except LanRouteError:
                continue
            if ip not in found:
                found.append(ip)
    return found

def merge_candidate_ips(routes: Iterable[object], *fallbacks: object) -> list[str]:
    candidates: list[tuple[int, str]] = []
    for raw in routes:
        if isinstance(raw, dict):
            value = raw.get("ip")
            priority = raw.get("priority", 50)
        else:
            value = raw
            priority = 50
        try:
            ip = normalize_private_ipv4(value)
        except LanRouteError:
            continue
        if isinstance(priority, bool) or not isinstance(priority, int):
            priority = 50
        candidates.append((priority, ip))
    for value in fallbacks:
        try:
            ip = normalize_private_ipv4(value)
        except LanRouteError:
            continue
        candidates.append((50, ip))
    result: list[str] = []
    for _priority, ip in sorted(candidates, key=lambda item: (item[0], item[1])):
        if ip not in result:
            result.append(ip)
    return result
