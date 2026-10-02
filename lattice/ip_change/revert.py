
import subprocess
import logging

logger = logging.getLogger(__name__)
def revert_to_old(interface, old_ip, gw, subnet_mask):
    apply_new_ip(interface, old_ip, gw, subnet_mask)

def fallback_dhcp(interface):
    subprocess.run(["nmcli", "con", "mod", interface, "ipv4.method", "auto"], check=True, timeout=30,)
    subprocess.run(["nmcli", "device", "reapply", interface], check=True, timeout=30,)