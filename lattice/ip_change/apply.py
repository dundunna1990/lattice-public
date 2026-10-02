
import subprocess
import logging

logger = logging.getLogger(__name__)
import time
def apply_new_ip(interface, new_ip, gw, subnet_mask):
    cmd = ["nmcli", "con", "mod", interface, "ipv4.method", "manual",
           "ipv4.addresses", f"{new_ip}/{subnet_mask}",
           "ipv4.gateway", gw]
    subprocess.run(cmd, check=True, timeout=30,)
    subprocess.run(["nmcli", "device", "reapply", interface], check=True, timeout=30,)
    time.sleep(2)