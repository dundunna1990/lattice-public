#!/usr/bin/env python3
"""
Lattice CLI – main entry point.
"""
import sys
import logging

logger = logging.getLogger(__name__)
import argparse
import os
from pathlib import Path
from lattice.cli.broadcast import register_subparser as broadcast_subparser
from lattice.cli.tui import get_status, run_tui
from lattice.cli.commands.autoheal import register_autoheal_commands, handle_autoheal
from lattice.cli.commands.status import cmd_status
from lattice.cli.commands.workers import cmd_workers
from lattice.cli.commands.alerts import cmd_alerts
from lattice.cli.commands.events import cmd_events
from lattice.cli.commands.config import cmd_config
from lattice.cli.commands.wipe import cmd_wipe
from lattice.cli.commands.services import cmd_services
from lattice.cli.commands.logs import cmd_logs
from lattice.cli.commands.rekey import cmd_rekey
from lattice.cli.commands.system import cmd_system
from lattice.cli.commands.backup_recovery import cmd_backup_recovery
from lattice.cli.commands.pairing import cmd_pairing
from lattice.cli.commands.mounts import cmd_mounts
from lattice.cli.commands.shell import cmd_shell
from lattice.wizard.orchestration import run_wizard
from lattice.operator_client import OperatorClientError
CONFIG_PATH = "/etc/lattice/lattice.toml"

_MASTER_ONLY_COMMANDS = {
    "workers", "mounts", "shell", "alerts", "events",
    "services", "rekey", "autoheal",
}

def _refuse_master_only_command_on_worker(command: str) -> bool:
    if command not in _MASTER_ONLY_COMMANDS:
        return False
    try:
        from lattice.operator_client import request
        local_status = request("status")
    except Exception:
        return False
    if isinstance(local_status, dict) and local_status.get("role") == "worker":
        print(
            "This is a Lattice Worker. Fleet-wide commands are available "
            "on the Lattice Master."
        )
        return True
    return False

def _run_main_tui() -> int:
    """Open the existing Lattice status/menu TUI and dispatch its selection."""
    try:
        status = get_status()
    except Exception as e:
        print(f"Error loading status: {e}")
        return 1

    # All normal dashboard controls now run inside curses.  run_tui returns
    # only when the operator exits (or after a successful full reset).
    run_tui(status)
    return 0


def cmd_init(args):
    """First-time wizard, then the existing Master TUI on successful setup."""
    import curses
    completed = curses.wrapper(run_wizard)
    if completed is not True:
        return 1

    from lattice.wizard.lifecycle import current_role
    if current_role() == "master" and os.path.exists(CONFIG_PATH):
        return _run_main_tui()
    return 0


def cmd_re_run(args):
    """Interactive re-run menu (TUI)."""
    if not os.path.exists(CONFIG_PATH):
        print("No configuration found. Run lattice init first.")
        return 1
    return _run_main_tui()

def main():
    parser = argparse.ArgumentParser(description="Lattice – LAN mesh manager")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    parser_init = subparsers.add_parser("init", help="First‑time setup wizard")

    # re-run
    subparsers.add_parser("re-run", help="Interactive re‑run menu (TUI)")
    # Status
    parser_status = subparsers.add_parser("status", help="Show mesh health")
    parser_status.set_defaults(func=cmd_status)

    # Workers
    parser_workers = subparsers.add_parser("workers", help="Manage workers")
    parser_workers.add_argument("action", choices=["list", "get", "recheck", "repair-network", "remove", "add"], help="Action to perform")
    parser_workers.add_argument("hostname", nargs="?", help="Worker hostname")
    parser_workers.set_defaults(func=cmd_workers)

    # Pairing (run on the worker itself; approval deliberately requires sudo)
    parser_pairing = subparsers.add_parser("pairing", help="View, approve, or locally revoke a worker pairing")
    parser_pairing.add_argument("action", choices=["status", "approve", "revoke", "repair-recovery"])
    parser_pairing.add_argument("fingerprint", nargs="?", help="Expected Master recovery SSH SHA256 fingerprint")
    parser_pairing.set_defaults(func=cmd_pairing)

    # Peer file mounts
    parser_mounts = subparsers.add_parser(
        "mounts",
        help="View or control persistent peer file mounts",
    )
    parser_mounts.add_argument(
        "action",
        choices=[
            "list",
            "fleet",
            "get",
            "mount",
            "unmount",
            "pause",
            "resume",
        ],
    )
    parser_mounts.add_argument(
        "peer",
        nargs="?",
        help="Immutable peer Node ID",
    )
    parser_mounts.set_defaults(
        func=cmd_mounts
    )

    # Trusted shell channel visibility (normal SSH commands still use ssh/scp/rsync directly).
    parser_shell = subparsers.add_parser(
        "shell", help="View trusted shell connection state and connection-only history"
    )
    parser_shell.add_argument("action", choices=["status", "history"])
    parser_shell.add_argument("--limit", type=int, default=100, help="History rows")
    parser_shell.set_defaults(func=cmd_shell)

    # Alerts
    parser_alerts = subparsers.add_parser("alerts", help="Manage alerts")
    parser_alerts.add_argument("action", choices=["list", "get", "ack"], help="Action to perform")
    parser_alerts.add_argument("id", nargs="?", help="Alert ID")
    parser_alerts.set_defaults(func=cmd_alerts)

    # Events
    parser_events = subparsers.add_parser("events", help="View events")
    parser_events.add_argument("--worker", help="Filter by worker")
    parser_events.add_argument("-n", type=int, default=50, help="Number of events")
    parser_events.set_defaults(func=cmd_events)

    # Config
    parser_config = subparsers.add_parser("config", help="Get/set config")
    parser_config.add_argument("action", choices=["get", "set"], help="Action")
    parser_config.add_argument("key", nargs="?", help="Config key")
    parser_config.add_argument("value", nargs="?", help="Config value")
    parser_config.set_defaults(func=cmd_config)

    # Wipe
    parser_wipe = subparsers.add_parser("wipe", help="Wipe everything")
    parser_wipe.set_defaults(func=cmd_wipe)

    # Rekey
    parser_rekey = subparsers.add_parser("rekey", help="Rotate one worker credential by revoke-and-re-pair")
    parser_rekey.add_argument("--all", action="store_true", help="Refused: rotate peers individually")
    parser_rekey.add_argument("peer", nargs="?", help="Specific peer hostname")
    parser_rekey.set_defaults(func=cmd_rekey)








    # Services
    parser_services = subparsers.add_parser("services", help="Manage services")
    parser_services.add_argument("action", choices=["list", "get"], help="Action to perform")
    parser_services.add_argument("name", nargs="?", help="Service name")
    parser_services.add_argument("--worker", help="Worker hostname")
    parser_services.set_defaults(func=cmd_services)

    # Logs
    parser_logs = subparsers.add_parser("logs", help="Tail daemon log")
    parser_logs.add_argument("-n", type=int, default=50, help="Lines")
    parser_logs.add_argument("--follow", "-f", action="store_true")
    parser_logs.set_defaults(func=cmd_logs)

    # Independent Backup disaster-recovery kit
    parser_backup_recovery = subparsers.add_parser(
        "backup-recovery",
        help="Export or use an encrypted source-independent Backup recovery kit",
    )
    parser_backup_recovery.add_argument("action", choices=["export", "inspect", "extract"])
    parser_backup_recovery.add_argument("path", help="Absolute encrypted recovery-kit path")
    parser_backup_recovery.add_argument(
        "destination", nargs="?",
        help="Absolute protected workspace path (required for extract)",
    )
    parser_backup_recovery.set_defaults(func=cmd_backup_recovery)

    # System (Boot & Resilience Layer operator commands)
    parser_system = subparsers.add_parser("system", help="Operate the lattice systemd stack")
    parser_system.add_argument("action", choices=["status", "restart", "stop", "start", "logs", "test-reboot", "verify-units"], help="Action to perform")
    parser_system.add_argument("target", nargs="?", default="all", choices=["all", "master", "worker", "init", "boot-recovery"], help="Target service (for restart/stop/start)")
    parser_system.add_argument("-n", type=int, default=100, help="Lines (for logs)")
    parser_system.add_argument("--follow", "-f", action="store_true", help="Follow log output")
    parser_system.set_defaults(func=cmd_system)



    broadcast_subparser(subparsers)
    register_autoheal_commands(subparsers)

    args = parser.parse_args()

    if _refuse_master_only_command_on_worker(args.command):
        return 1

    if args.command == "autoheal":
        return handle_autoheal(args)
    if args.command == "init":
        return cmd_init(args)
    elif args.command == "re-run":
        return cmd_re_run(args)
    else:
        # Try to dispatch to command-specific functions
        if hasattr(args, "func"):
            try:
                return args.func(args)
            except OperatorClientError as exc:
                print(f"Lattice operator error: {exc}", file=sys.stderr)
                if "Permission denied" in str(exc):
                    print("If Lattice was just installed, log out and back in so lattice-operator group membership becomes active.", file=sys.stderr)
                return 1
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
