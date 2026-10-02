
import subprocess
import logging

logger = logging.getLogger(__name__)
import ipaddress
import socket

def check_same_subnet(old_ip, new_ip):
    old = ipaddress.ip_address(old_ip)
    new = ipaddress.ip_address(new_ip)
    # assume /24 for simplicity
    return old.packed[:3] == new.packed[:3]  # M25: hardcoded /24, should auto-detect netmask

def arp_check(ip):
    result = subprocess.run(["arping", "-c", "1", "-w", "1", ip], capture_output=True, timeout=15,)
    return result.returncode != 0  # 0 means found, so conflict

def gateway_reachable(gw):
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", gw], check=True, capture_output=True, timeout=15,)
        return True
    except (OSError, socket.error):
        return False

def worker_reachable(worker_ip):
    try:
        sock = socket.create_connection((worker_ip, 9999), timeout=2)
        sock.close()
        return True
    except (OSError, socket.error):
        return False

def preflight(old_ip, new_ip, gw, workers):
    if not check_same_subnet(old_ip, new_ip):
        return False, "Subnet mismatch"
    if not arp_check(new_ip):
        return False, "ARP conflict"
    if not gateway_reachable(gw):
        return False, "Gateway unreachable"
    for w in workers:
        if not worker_reachable(w):
            return False, f"Worker {w} unreachable"
    return True, "OK"