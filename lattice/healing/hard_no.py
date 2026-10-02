"""
Hard no-heal list (Decision 12 B+ bulletproof).
Defines actions that auto-heal should NEVER perform.
"""
import logging
from typing import List, Set

logger = logging.getLogger(__name__)

# Hard no-heal categories (by service name or action pattern)
# These are hardcoded; they cannot be overridden by config.
HARD_NO_CATEGORIES = {
    # Authentication
    "sshd",
    "sudo",
    "auth",
    "shadow",
    "passwd",
    "authorized_keys",
    # Firewall
    "ufw",
    "iptables",
    "firewalld",
    "nftables",
    # Network config
    "NetworkManager",
    "systemd-networkd",
    "network",
    "resolv.conf",
    "hosts",
    # Packages
    "apt",
    "dpkg",
    "snap",
    "dnf",
    "yum",
    "zypper",
    # Kernel & boot
    "kernel",
    "boot",
    "initramfs",
    "grub",
    "systemd",
    # TLS / keys
    "tls",
    "ssl",
    "gpg",
    # Critical system paths
    "/etc/systemd/system",
    "/etc/cron",
    "/etc/sudoers",
}

# Normal unattended healing is intentionally narrow. It is limited to the
# Lattice processes themselves until a later, explicitly designed approval
# workflow exists for other services.
MANAGED_LATTICE_SERVICES = {"lattice-worker"}

ALLOWED_AUTOHEAL_ACTIONS = {"restart"}

# Specific commands that are forbidden even if service is not in the list
FORBIDDEN_COMMANDS = {
    "systemctl restart sshd",           # use reload instead
    "systemctl restart NetworkManager", # would drop network
    "systemctl restart systemd-networkd",
    "apt install",
    "apt remove",
    "dpkg -i",
    "chmod",
    "chown",
    "rm -rf",
}

def is_hard_no(action: str, service_name: str = None) -> bool:
    """
    Check if an action or service is in the hard no-heal list.
    Returns True if auto-heal should NEVER touch it.
    """
    action_lower = action.lower()
    # Check service name against categories
    if service_name:
        service_lower = service_name.lower()
        for category in HARD_NO_CATEGORIES:
            if category in service_lower or service_lower in category:
                logger.debug(f"Hard no-heal: service '{service_name}' matches category '{category}'")
                return True

    # Check action against forbidden commands
    for forbidden in FORBIDDEN_COMMANDS:
        if forbidden.lower() in action_lower:
            logger.debug(f"Hard no-heal: action '{action}' matches forbidden command '{forbidden}'")
            return True

    return False


def is_autoheal_action_allowed(action: str, service_name: str) -> bool:
    """Return whether an unattended worker action is safe to execute.

    This is deliberately stricter than command syntax validation. A valid
    systemd unit is not automatically safe to control. The same policy is
    used by the master and the worker HTTP endpoint.
    """
    normalized_action = action.lower().strip()
    normalized_service = service_name.lower().strip()
    if normalized_service.endswith(".service"):
        normalized_service = normalized_service[:-8]

    if normalized_action not in ALLOWED_AUTOHEAL_ACTIONS:
        return False
    if is_hard_no(normalized_action, normalized_service):
        return False
    return normalized_service in MANAGED_LATTICE_SERVICES

def get_hard_no_list() -> List[str]:
    """Return the list of hard no-heal categories for documentation/UI."""
    return sorted(list(HARD_NO_CATEGORIES))
