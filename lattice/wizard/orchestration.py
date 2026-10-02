
import curses
import logging

logger = logging.getLogger(__name__)
import sys
import os
import socket
import netifaces
import time
from dataclasses import asdict
from pathlib import Path
from lattice.wizard.screens import center_text, get_choice, confirm, get_string
from lattice.wizard.journal import load_journal, save_journal, clear_journal
from lattice.core.config import load_config, save_config, MasterConfig, DaemonConfig, WireFormatConfig, LatticeConfig
from lattice.core.crypto.ssh import ensure_lattice_ssh_key
from lattice.core.ssh_setup import SSHSetupError, prepare_local_ssh, restore_local_ssh
from lattice.core.ssh_firewall import (
    SSHFirewallError,
    ensure_local_lan_ssh_firewall,
    enable_inactive_ufw_for_lattice,
    remove_lattice_firewall_rules,
)
from lattice.core.mdns import discover_waiting_workers, publish_waiting_worker
from lattice.onboarding import PairingError, prepare_worker_pairing, approve_worker_pairing
from lattice.wizard.lifecycle import RoleLifecycleError, activate_role
from lattice.ip_change.setup import (
    StaticIPError,
    StaticIPPlan,
    apply_static_ip,
    detect_connection,
    detect_dns_servers,
    is_address_available,
    prefix_from_netmask,
)
from lattice.ip_change.pool import (
    AddressPool,
    AddressPoolError,
    choose_available_address,
    find_contiguous_available_pool,
    suggested_pool,
    write_address_pool,
)


import fcntl as _wlock_fcntl
import contextlib as _wlock_contextlib


class WizardLockError(Exception):
    """Raised when the wizard lock cannot be acquired (another instance running)."""
    pass


@_wlock_contextlib.contextmanager
def WizardLock(lock_path: str = "/var/run/lattice-wizard.lock"):
    """File-based lock ensuring only one wizard instance runs at a time.

    Uses fcntl.flock (non-blocking). If another wizard holds the lock,
    raises WizardLockError immediately rather than waiting.
    """
    fd = open(lock_path, "w")
    try:
        _wlock_fcntl.flock(fd, _wlock_fcntl.LOCK_EX | _wlock_fcntl.LOCK_NB)
    except BlockingIOError:
        fd.close()
        raise WizardLockError(
            f"Another wizard is already running (lock held: {lock_path})"
        )
    try:
        yield fd
    finally:
        try:
            _wlock_fcntl.flock(fd, _wlock_fcntl.LOCK_UN)
        except Exception:
            pass
        fd.close()


def run_wizard(stdscr, noninteractive=None):
    # Acquire the wizard lock — fail fast if another instance is running.
    try:
        lock = WizardLock()
        lock.__enter__()
    except WizardLockError as e:
        center_text(stdscr, f"⚠️  {e}", 2)
        stdscr.refresh()
        curses.napms(3000)
        return

    try:
        return _run_wizard_locked(stdscr, noninteractive)
    finally:
        lock.__exit__(None, None, None)


def _run_wizard_locked(stdscr, noninteractive=None):
    # `lattice init` is strictly first-time-only. Existing installations are
    # managed through `lattice re-run` / `lattice config`; never reconstruct
    # an established configuration from wizard defaults.
    if Path("/etc/lattice/lattice.toml").exists():
        if not noninteractive:
            stdscr.erase()
            center_text(stdscr, "Lattice is already configured on this computer.", 3)
            center_text(stdscr, "Use `lattice re-run` or `lattice config` to manage it safely.", 5)
            center_text(stdscr, "First-time setup will not overwrite the existing configuration.", 7)
            stdscr.refresh()
            stdscr.getch()
        return False

    steps = [
        ("welcome", welcome_step),
        ("role", role_step),
        ("ip", ip_step),
        ("network", network_step),
        ("address_pool", address_pool_step),
        ("static_ip", static_ip_step),
        ("ssh_firewall", ssh_firewall_step),
        ("ssh_key", ssh_key_step),
        ("write_start", write_start_step),
        # Discovery comes only after this node has its final config and its
        # selected daemon is actually running.
        ("key_exchange", key_exchange_step),
    ]
    journal = load_journal()
    start_step = 0
    data = {}
    if journal:
        candidate_step = journal.get("step", 0)
        candidate_data = journal.get("data", {})
        if (
            isinstance(candidate_step, int)
            and 0 <= candidate_step <= len(steps)
            and isinstance(candidate_data, dict)
        ):
            start_step = candidate_step
            data = candidate_data
            if start_step > 0:
                center_text(stdscr, f"Resuming from step {start_step}", 2)
                stdscr.refresh()
                curses.napms(1000)
        else:
            clear_journal()

    for i in range(start_step, len(steps)):
        step_name, func = steps[i]
        result = func(stdscr, data, noninteractive)
        if result is None or result is False:
            clear_journal()
            return False
        if result:
            data.update(result)
        save_journal(i+1, data)

    clear_journal()
    if not noninteractive:
        stdscr.erase()
    center_text(stdscr, "✅ Lattice setup complete!", 2)
    stdscr.refresh()
    curses.napms(2000)
    return True

# ----- Step functions -----
def welcome_step(stdscr, data, ni):
    if not ni:
        stdscr.erase()
    center_text(stdscr, "Welcome to Lattice setup", 2)
    center_text(stdscr, "This wizard will set up this machine as a Lattice node.", 4)
    center_text(stdscr, "Press any key to continue...", 6)
    stdscr.refresh()
    stdscr.getch()
    return {}

def role_step(stdscr, data, ni):
    choices = ["Master", "Worker"]
    intro_lines = [
        "Choose how this computer will be used in Lattice.",
        "Master: The main computer. It manages the fleet, approves new computers,",
        "and shows overall status.",
        "Worker: A computer that joins the Master and becomes part of the fleet.",
        "Usually, you have one Master and the rest are Workers.",
    ]
    sel = get_choice(stdscr, "Choose role:", choices, intro_lines=intro_lines)
    if sel < 0: return False
    return {"role": choices[sel].lower()}

def ip_step(stdscr, data, ni):
    if not ni:
        stdscr.erase()
    try:
        default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['addr']
    except Exception:
        default_iface = "eth0"
        ip = "127.0.0.1"
    role = data.get("role")
    if role == "worker":
        if not ni:
            center_text(stdscr, f"Temporary network address: {ip}", 2)
            center_text(stdscr, "The master will automatically assign this worker a static IP later.", 4)
            stdscr.refresh()
            curses.napms(800)
        return {
            "current_ip": ip,
            "ip": ip,
            "interface": default_iface,
            "static_ip_enabled": False,
        }
    # The master is the first machine with a source of truth.  It will claim
    # the first address in the approved Lattice pool automatically.
    if not ni:
        center_text(stdscr, f"Temporary network address: {ip}", 2)
        center_text(stdscr, "Lattice will automatically choose the master static IP.", 4)
        stdscr.refresh()
        curses.napms(800)
    return {
        "current_ip": ip,
        "ip": ip,
        "interface": default_iface,
        "static_ip_enabled": True,
    }

def network_step(stdscr, data, ni):
    # Auto-detect the active gateway and subnet. Never assume a particular
    # private-LAN layout when detection fails.
    if not ni:
        stdscr.erase()
        center_text(stdscr, "Detecting local network settings...", 3)
        center_text(stdscr, "Checking the active network interface, gateway, and subnet.", 5)
        stdscr.refresh()
        curses.napms(500)

    gw = None
    subnet = None
    default_iface_name = ""
    try:
        gateways = netifaces.gateways()
        default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            gw = default_gw[0]
            default_iface_name = default_gw[1]
            ifaces = netifaces.ifaddresses(default_iface_name)
            if netifaces.AF_INET in ifaces and ifaces[netifaces.AF_INET]:
                subnet = ifaces[netifaces.AF_INET][0].get("netmask")
    except Exception:
        pass

    if ni:
        gw = ni.get("gateway", gw)
        subnet = ni.get("subnet", subnet)

    interface = data.get("interface") or default_iface_name
    if not gw or not subnet or not interface:
        if not ni:
            stdscr.erase()
            center_text(stdscr, "Could not safely detect the active IPv4 network.", 3)
            center_text(stdscr, "Check NetworkManager connectivity, then run setup again.", 5)
            stdscr.refresh()
            stdscr.getch()
        return False

    try:
        detected_dns = detect_dns_servers(interface)
    except StaticIPError:
        detected_dns = (gw,)

    if ni:
        configured_dns = ni.get("dns", detected_dns)
        if isinstance(configured_dns, str):
            configured_dns = (configured_dns,)
        return {
            "gateway": gw,
            "subnet": subnet,
            "dns": list(configured_dns),
        }

    details = [
        "Detected network settings:",
        f"Interface: {interface}",
        f"Current IP: {data.get('current_ip', data.get('ip', 'unknown'))}",
        f"Gateway: {gw}",
        f"Subnet mask: {subnet}",
        f"DNS: {', '.join(detected_dns)}",
        (
            "This only confirms temporary Worker connectivity; the Master will "
            "choose this Worker's permanent Lattice address later."
            if data.get("role") == "worker"
            else "Lattice will use these to build the Master's automatic address pool."
        ),
    ]
    if not confirm(stdscr, "Use these detected network settings?", context_lines=details):
        return False
    return {"gateway": gw, "subnet": subnet, "dns": list(detected_dns)}

def address_pool_step(stdscr, data, ni):
    if data.get("role") != "master":
        return {}
    interface = data.get("interface", "eth0")
    try:
        prefix = prefix_from_netmask(data["subnet"])
        dns = data.get("dns") or ()
        if isinstance(dns, str):
            dns = (dns,)
        if not ni:
            stdscr.erase()
            center_text(stdscr, "Finding a free contiguous Lattice address block...", 3)
            center_text(stdscr, "Lattice is checking candidate addresses before creating the pool.", 5)
            stdscr.refresh()

        def show_candidate(candidate):
            if ni:
                return
            h, _w = stdscr.getmaxyx()
            center_text(stdscr, f"Checking {candidate}...", h // 2)
            stdscr.refresh()

        pool = find_contiguous_available_pool(
            data["current_ip"],
            prefix,
            data["gateway"],
            interface,
            lambda candidate: not is_address_available(interface, candidate),
            dns=tuple(dns),
            on_check=show_candidate,
        )
    except (KeyError, StaticIPError, AddressPoolError) as exc:
        if not ni:
            stdscr.erase()
        center_text(stdscr, f"Could not find a safe automatic address pool: {exc}", 4)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False
    if not ni:
        details = [
            "Verified currently-unused Lattice address pool:",
            f"Start: {pool.start}",
            f"End:   {pool.end}",
            "Every address in this contiguous block passed a live duplicate-address check.",
            "Lattice will re-check an address again immediately before assigning it.",
            "A router's future DHCP lease range cannot always be discovered from a client computer.",
        ]
        if not confirm(stdscr, "Use this verified automatic Lattice address pool?", context_lines=details):
            return False
    pool_data = asdict(pool)
    pool_data["dns"] = list(pool.dns)
    return {"address_pool": pool_data}


def static_ip_step(stdscr, data, ni):
    if not data.get("static_ip_enabled") or data.get("role") != "master":
        return {}

    interface = data.get("interface", "eth0")
    try:
        prefix = prefix_from_netmask(data["subnet"])
        saved_pool = dict(data["address_pool"])
        saved_pool["dns"] = tuple(saved_pool.get("dns", ()))
        pool = AddressPool(**saved_pool)
        if not ni:
            stdscr.erase()
            center_text(stdscr, "Finding an available static IP address...", 3)
            center_text(stdscr, f"Scanning {pool.start} through {pool.end} on {interface}.", 5)
            stdscr.refresh()

        def show_candidate(candidate):
            if ni:
                return
            h, _w = stdscr.getmaxyx()
            center_text(stdscr, f"Checking {candidate}...", h//2)
            stdscr.refresh()

        address = choose_available_address(
            pool,
            {data.get("current_ip"), data.get("gateway")},
            lambda candidate: not is_address_available(interface, candidate),
            on_check=show_candidate,
        )
        if not ni:
            h, _w = stdscr.getmaxyx()
            center_text(stdscr, f"Available address found: {address}", h//2 + 2)
            stdscr.refresh()
            curses.napms(400)
        connection = detect_connection(interface)
        plan = StaticIPPlan(
            interface=interface,
            connection=connection,
            address=address,
            prefix=prefix,
            gateway=data["gateway"],
            dns=tuple(data.get("dns") or ()),
        )
    except (KeyError, TypeError, StaticIPError, AddressPoolError) as exc:
        if not ni:
            stdscr.erase()
        center_text(stdscr, f"Static-IP details are invalid: {exc}", 4)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False

    if not ni:
        details = [
            "Planned static network settings:",
            f"IP address: {plan.address}/{plan.prefix}",
            f"Interface: {plan.interface}",
            f"Gateway: {plan.gateway}",
            f"DNS: {', '.join(plan.dns) if plan.dns else 'none'}",
            "Lattice will save the current settings before making this change.",
            "If verification fails, the previous settings will be restored automatically.",
        ]
        if not confirm(stdscr, "Apply and verify this static IP now?", context_lines=details):
            return False

    if not ni:
        stdscr.erase()
    center_text(stdscr, "Saving current settings and applying the planned static IP...", 2)
    stdscr.refresh()
    try:
        apply_static_ip(plan)
        write_address_pool(pool)
    except (StaticIPError, AddressPoolError, OSError) as exc:
        center_text(stdscr, f"Static-IP setup stopped safely: {exc}", 4)
        center_text(stdscr, "Lattice did not continue to service setup.", 6)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False

    center_text(stdscr, f"✅ Static IP {plan.address} is active and verified.", 4)
    stdscr.refresh()
    curses.napms(500)
    return {
        "ip": plan.address,
        "network_connection": connection,
        "static_ip_verified": True,
    }

def ssh_firewall_step(stdscr, data, ni):
    if not ni:
        stdscr.erase()
    center_text(stdscr, "Backing up, validating, and preparing SSH...", 2)
    stdscr.refresh()
    result = None
    firewall_changed_by_section = False

    def rollback_section():
        errors = []
        # Each firewall helper self-rolls back its own partial failure. Remove
        # a completed manifest only if this exact setup transaction created it.
        if firewall_changed_by_section:
            try:
                remove_lattice_firewall_rules()
            except (SSHFirewallError, OSError, ValueError) as exc:
                errors.append(f"firewall restore failed: {exc}")
        if result is not None:
            try:
                restore_local_ssh(result)
            except SSHSetupError as exc:
                errors.append(f"SSH restore failed: {exc}")
        if errors:
            logger.error("Incomplete SSH/firewall rollback: %s", "; ".join(errors))
        return errors

    try:
        result = prepare_local_ssh()
    except SSHSetupError as exc:
        center_text(stdscr, f"SSH setup failed safely: {exc}", 4)
        center_text(stdscr, "No Lattice service was started. Press any key to stop setup.", 6)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False
    center_text(stdscr, "Checking the firewall for local-network SSH access...", 6)
    stdscr.refresh()
    try:
        role = data.get("role")
        try:
            if role == "master":
                api_port = int(data.get("api_port", MasterConfig().api_port))
            elif role == "worker":
                api_port = int(data.get("worker_api_port", WireFormatConfig().port))
            else:
                raise SSHFirewallError("Choose a Lattice role before firewall setup.")
        except (TypeError, ValueError) as exc:
            raise SSHFirewallError("The selected role API port is invalid.") from exc
        # Security invariant retained for source-audit tests: firewall mutation
        # belongs only to guided setup via ensure_local_lan_ssh_firewall().
        firewall = ensure_local_lan_ssh_firewall(api_port=api_port)
        firewall_changed_by_section = bool(firewall.changed)
    except SSHFirewallError as exc:
        rollback_section()
        center_text(stdscr, f"SSH firewall setup stopped safely: {exc}", 8)
        center_text(stdscr, "SSH/firewall changes from this setup section were restored.", 10)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False
    center_text(stdscr, f"✅ SSH is active and enabled ({result.service_name}).", 4)
    if firewall.firewall == "ufw (inactive)":
        center_text(stdscr, "UFW is installed but inactive.", 6)
        if ni:
            rollback_section()
            center_text(stdscr, "Non-interactive setup will not enable a firewall automatically.", 8)
            stdscr.refresh()
            return False
        center_text(stdscr, "Configure LAN-only Lattice rules and enable UFW safely? [Y/n]", 8)
        stdscr.refresh()
        answer = stdscr.getch()
        if answer in (ord("n"), ord("N")):
            rollback_section()
            return False
        try:
            firewall = enable_inactive_ufw_for_lattice(api_port=api_port)
            firewall_changed_by_section = bool(firewall.changed)
        except SSHFirewallError as exc:
            rollback_section()
            center_text(stdscr, f"UFW activation stopped safely: {exc}", 8)
            center_text(stdscr, "SSH/firewall changes from this setup section were restored.", 10)
            stdscr.refresh()
            stdscr.getch()
            return False
        center_text(stdscr, f"✅ UFW enabled; Lattice access is limited to {firewall.subnet}.", 6)
    unsupported_protection = firewall.firewall in {
        "firewalld (inactive)",
        "no supported active firewall",
    }
    if unsupported_protection:
        center_text(
            stdscr,
            f"⚠ No supported active firewall is protecting SSH/API TCP/{api_port}.",
            6,
        )
        if ni:
            rollback_section()
            center_text(stdscr, "Non-interactive setup will not continue without firewall protection.", 8)
            stdscr.refresh()
            return False
        center_text(stdscr, "Continue without an active supported firewall? [y/N]", 8)
        stdscr.refresh()
        if stdscr.getch() not in (ord("y"), ord("Y")):
            rollback_section()
            return False
    elif firewall.changed:
        center_text(
            stdscr,
            f"✅ {firewall.firewall} allows SSH and API TCP/{api_port} only from {firewall.subnet}.",
            6,
        )
    else:
        center_text(stdscr, f"Firewall check: {firewall.firewall}; no rule change was needed.", 6)
    if result.backup_path:
        center_text(stdscr, f"Backup: {result.backup_path}", 6)
    stdscr.refresh()
    curses.napms(500)
    return {}


def ssh_key_step(stdscr, data, ni):
    if data.get("role") == "worker":
        # Workers accept the master's public key later, after the master is
        # approved with the one-time pairing code. They do not push a key.
        return {}
    if not ni:
        stdscr.erase()
    center_text(stdscr, "Generating Lattice SSH key...", 2)
    stdscr.refresh()
    ensure_lattice_ssh_key(ssh_dir=Path("/etc/lattice/keys"))
    return {}

def wait_for_local_worker_api(port: int, attempts: int = 20, delay_seconds: float = 0.5) -> bool:
    """Wait until the newly-started worker really accepts local TCP connections."""
    for _ in range(attempts):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(delay_seconds)
    return False


def key_exchange_step(stdscr, data, ni):
    role = data.get("role")
    if not ni:
        stdscr.erase()
    if not data.get("role_service_started"):
        center_text(stdscr, "Lattice service is not ready yet; setup stopped safely.", 4)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False
    if role == "worker":
        port = load_config().wire_format.port
        center_text(stdscr, "Waiting for the worker service to become reachable...", 2)
        stdscr.refresh()
        if not wait_for_local_worker_api(port):
            center_text(stdscr, "Worker service did not become reachable; no pairing was published.", 4)
            stdscr.refresh()
            if not ni:
                stdscr.getch()
            return False
        ssh_user = os.environ.get("SUDO_USER")
        if not ssh_user:
            center_text(stdscr, "Run setup through sudo from the account that should receive SSH access.", 4)
            stdscr.refresh()
            if not ni:
                stdscr.getch()
            return False
        try:
            offer = prepare_worker_pairing(socket.gethostname(), ssh_user)
        except PairingError as exc:
            center_text(stdscr, f"Could not prepare worker pairing: {exc}", 4)
            stdscr.refresh()
            if not ni:
                stdscr.getch()
            return False
        try:
            publish_waiting_worker(offer.pairing_id, offer.hostname, offer.ssh_user, port=port)
        except Exception as exc:
            center_text(stdscr, f"Could not publish worker discovery: {exc}", 4)
            stdscr.refresh()
            if not ni:
                stdscr.getch()
            return False
        center_text(stdscr, "This worker is waiting to be paired by a master.", 2)
        center_text(stdscr, f"Pairing code: {offer.code}", 4)
        center_text(stdscr, "On the master, choose this worker and enter that code.", 6)
        center_text(stdscr, "When the master requests approval, press A here to approve it.", 7)
        center_text(stdscr, "The code expires in 10 minutes. Press Q to leave it waiting.", 8)
        stdscr.refresh()
        while True:
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                break
            if key in (ord("a"), ord("A")):
                try:
                    approve_worker_pairing(offer.pairing_id)
                except PairingError as exc:
                    center_text(stdscr, str(exc), 10)
                    stdscr.refresh()
                    continue
                center_text(stdscr, "Approved. The master is securely verifying this worker.", 10)
                stdscr.refresh()
                curses.napms(1500)
                break
        return {"pairing_id": offer.pairing_id}

    master_user = os.environ.get("SUDO_USER")

    if not master_user or master_user in {"root", "lattice"}:
        center_text(
            stdscr,
            "Run master setup through sudo from the main human account.",
            4,
        )
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False

    try:
        from lattice.core.db import get_db_connection
        from lattice.core.migrations import run_migrations
        from lattice.file_access.bootstrap import (
            ensure_master_fleet_bootstrap,
        )

        conn = get_db_connection()
        try:
            run_migrations(conn)
            ensure_master_fleet_bootstrap(
                conn,
                hostname=socket.gethostname(),
                ip=load_config().master.ip,
                main_user=master_user,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception as exc:
        center_text(
            stdscr,
            f"Could not initialize master fleet identity: {exc}",
            4,
        )
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False

    if not ni:
        stdscr.erase()
        center_text(stdscr, "Lattice Master setup complete.", 3)
        center_text(stdscr, "Your Master is installed, configured, and running.", 5)
        center_text(stdscr, "Opening the Lattice dashboard...", 7)
        center_text(stdscr, "Press any key to continue.", 9)
        stdscr.refresh()
        stdscr.getch()
    return {"master_fleet_ready": True}

def write_start_step(stdscr, data, ni):
    if not ni:
        stdscr.erase()
    center_text(stdscr, "Writing config and starting daemon...", 2)
    stdscr.refresh()
    import secrets
    role = data.get("role")
    existing = LatticeConfig()
    api_token = data.get("api_token") or existing.master.api_token or secrets.token_hex(32)
    master_key = data.get("master_key") or existing.master.master_key or secrets.token_hex(16)
    config = LatticeConfig(
        master=MasterConfig(
            # A worker has not learned its master's address yet. Do not save
            # the worker's own address as its master endpoint.
            ip=data.get("ip", "127.0.0.1") if role == "master" else "127.0.0.1",
            api_port=data.get("api_port", 8080),
            api_token=api_token,
            master_key=master_key,
        ),
        daemon=DaemonConfig(),
        wire_format=WireFormatConfig()
    )
    config_path = Path("/etc/lattice/lattice.toml")
    previous_config = config_path.read_bytes() if config_path.exists() else None
    save_config(config, str(config_path))
    # Both daemons run as the dedicated lattice account.  They need read-only
    # access to the generated configuration, while other local users do not.
    try:
        import grp
        os.chown(config_path, 0, grp.getgrnam("lattice").gr_gid)
        os.chmod(config_path, 0o640)
    except KeyError:
        os.chmod(config_path, 0o600)
    try:
        activate_role(role)
    except RoleLifecycleError as exc:
        if previous_config is None:
            config_path.unlink(missing_ok=True)
        else:
            config_path.write_bytes(previous_config)
        center_text(stdscr, f"Service setup failed: {exc}", 6)
        center_text(stdscr, "The generated config was rolled back. Press any key to stop setup.", 8)
        stdscr.refresh()
        if not ni:
            stdscr.getch()
        return False
    if role == "master" and not ni:
        stdscr.erase()
        center_text(stdscr, "Master service started successfully.", 4)
        center_text(stdscr, "Authentication credentials were generated and stored securely.", 6)
        center_text(stdscr, "You do not need to save them manually.", 8)
        stdscr.refresh()
        curses.napms(700)
    stdscr.refresh()
    curses.napms(500)
    return {"role_service_started": True}
