from lattice.core.config import load_config

import subprocess
import logging

logger = logging.getLogger(__name__)
import time
import socket

def self_check(expected_ip):
    result = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True, timeout=30,)
    return expected_ip in result.stdout

def worker_check(worker_ip, expected_ip):
    try:
        # ping new IP from worker – simplified: just check worker's health endpoint
        _port = load_config().wire_format.port  # M26: from config

        sock = socket.create_connection((worker_ip, _port), timeout=2)
        sock.close()
        return True
    except (OSError, socket.error):
        return False

def verify_workers(workers, new_ip, timeout=300):
    start = time.time()
    while time.time() - start < timeout:
        all_ok = True
        for w in workers:
            if not worker_check(w, new_ip):
                all_ok = False
                break
        if all_ok:
            return True
        time.sleep(10)
    return False