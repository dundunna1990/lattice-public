import argparse
import logging

logger = logging.getLogger(__name__)
import json
from lattice.core.mdns import publish_service, stop_broadcast, preflight, discover_workers

def cmd_broadcast(args):
    if args.action == "start":
        try:
            preflight()
        except Exception as e:
            logger.error(f"Preflight failed: {e}; continuing anyway")
            # M31: don't crash on sudo apt install failure or other preflight errors
        try:
            publish_service(args.instance or "lattice-worker", port=args.port or 9999,
                            txt={"role": args.role or "worker", "version": "0.1.0"},
                            ssh_user=args.ssh_user)
            print(f"Broadcasting as '{args.instance or 'lattice-worker'}' on port {args.port or 9999}")
            return 0
        except RuntimeError as e:
            print(f"Failed to start: {e}")
            return 1
    elif args.action == "stop":
        stop_broadcast()
        print("Broadcast stopped.")
        return 0
    else:
        print("Unknown action")
        return 1

def cmd_discover(args):
    workers = discover_workers(timeout=args.timeout or 3)
    if args.json:
        print(json.dumps(workers, indent=2))
    else:
        if not workers:
            print("No workers found.")
        else:
            print(f"Found {len(workers)} worker(s):")
            for w in workers:
                # The parser returns dict with keys: iface, proto, host, addr, port, txt
                # Use 'host' as the display name (fallback to 'addr')
                display = w.get('host', w['addr'])
                print(f"  - {display} @ {w['addr']}:{w['port']}")
    return 0

def register_subparser(subparsers):
    parser = subparsers.add_parser("broadcast", help="mDNS broadcast control")
    parser.add_argument("action", choices=["start", "stop"], help="Start or stop broadcasting")
    parser.add_argument("--instance", help="Instance name (default: lattice-worker)")
    parser.add_argument("--port", type=int, default=9999, help="Service port")
    parser.add_argument("--role", default="worker", help="Role (TXT record)")
    parser.add_argument("--ssh-user", help="SSH username (TXT record)")
    parser.set_defaults(func=cmd_broadcast)

    discover_parser = subparsers.add_parser("discover", help="Discover workers via mDNS")
    discover_parser.add_argument("--timeout", type=int, default=3, help="Discovery timeout in seconds")
    discover_parser.add_argument("--json", action="store_true", help="JSON output")
    discover_parser.set_defaults(func=cmd_discover)
