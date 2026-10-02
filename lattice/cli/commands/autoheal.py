"""
CLI commands for auto-heal control.
"""
import argparse
import os
from lattice.core.db import get_db_connection
from lattice.core.config import set_config_value, get_config_value, load_config, save_config
from lattice.healing.engine import AutoHealEngine

def register_autoheal_commands(subparsers):
    """Register auto-heal subcommands."""
    parser = subparsers.add_parser("autoheal", help="Control auto-heal")
    sub = parser.add_subparsers(dest="autoheal_cmd", required=True)

    # autoheal enable
    enable_parser = sub.add_parser("enable", help="Enable auto-heal for a worker")
    enable_parser.add_argument("worker_id", type=int, help="Worker ID to enable")

    # autoheal disable
    disable_parser = sub.add_parser("disable", help="Disable auto-heal for a worker")
    disable_parser.add_argument("worker_id", type=int, help="Worker ID to disable")

    # autoheal status
    status_parser = sub.add_parser("status", help="Show auto-heal status")
    status_parser.add_argument("--worker-id", type=int, help="Worker ID to check")

    return parser

def handle_autoheal(args):
    """Execute auto-heal commands."""
    engine = AutoHealEngine()
    if args.autoheal_cmd in {"enable", "disable"} and os.geteuid() != 0:
        print("Changing auto-heal requires sudo on the Lattice Master.")
        return 1

    if args.autoheal_cmd == "enable":
        # This is the owner's explicit opt-in. Automatic mode remains off
        # unless the owner enables at least one worker from this local CLI.
        set_config_value("autoheal.mode", "automatic")
        engine._set_opt_in(args.worker_id, True)
        config = load_config()
        if config.daemon.dry_run:
            config.daemon.dry_run = False
            save_config(config)
        print(f"Auto-heal enabled for worker {args.worker_id}: it may restart only lattice-worker, at most twice in 15 minutes.")
    elif args.autoheal_cmd == "disable":
        engine._set_opt_in(args.worker_id, False)
        print(f"Auto-heal disabled for worker {args.worker_id}")
    elif args.autoheal_cmd == "status":
        if os.geteuid() != 0:
            from lattice.operator_client import request
            data = request("autoheal.status")
            print(f"Mode: {data['mode']}")
            workers = data.get("workers", [])
            if args.worker_id:
                workers = [row for row in workers if row.get("id") == args.worker_id]
            for row in workers:
                state = "enabled" if row.get("enabled") else "disabled"
                print(f"{row.get('hostname')} (ID {row.get('id')}): {state}")
            return 0
        print(f"Mode: {engine._mode()}")
        if args.worker_id:
            status = engine._get_opt_in_status(args.worker_id)
            print(f"Worker {args.worker_id}: {'enabled' if status else 'disabled'}")
        else:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, hostname FROM workers WHERE removed_at IS NULL")
            rows = cursor.fetchall()
            conn.close()
            for row in rows:
                status = engine._get_opt_in_status(row[0])
                print(f"{row[1]} (ID {row[0]}): {'enabled' if status else 'disabled'}")
        return 0
