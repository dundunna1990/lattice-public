"""Local, human-approved worker enrollment commands."""

import os
from pathlib import Path
import subprocess

from lattice.onboarding import (
    PairingError,
    approve_worker_pairing,
    get_local_pending_pairing_details,
    get_public_pairing_status,
)
from lattice.credential_revoke import revoke_local_pairing


def cmd_pairing(args) -> int:
    if args.action == "status":
        try:
            status = get_public_pairing_status()
        except PairingError as exc:
            print(f"Could not read pairing status: {exc}")
            return 1
        if not status:
            print("This worker is not waiting for or completing a pairing.")
            return 0
        print(f"Pairing status: {status['state']}")
        print(f"Worker: {status['hostname']}")
        if status.get("master_hostname"):
            print(f"Requested master: {status['master_hostname']}")
        details = get_local_pending_pairing_details()
        if details:
            print(f"Master address: {details['master_ip']}")
            print(f"Master key fingerprint: {details['key_fingerprint']}")
        return 0

    if args.action == "approve":
        try:
            details = get_local_pending_pairing_details()
            if not details:
                print("There is no pending master request to approve yet.")
                return 1
            print(f"Approving {details['master_hostname']} at {details['master_ip']}")
            print(f"Key fingerprint: {details['key_fingerprint']}")
            approve_worker_pairing(details["pairing_id"])
        except PairingError as exc:
            print(f"Pairing was not approved: {exc}")
            return 1
        print("Approved. The master will now verify the secure connection.")
        return 0

    if args.action == "repair-recovery":
        if os.geteuid() != 0:
            print("Recovery migration requires local administrator approval. Run with sudo.")
            return 1
        fingerprint = getattr(args, "fingerprint", None)
        if not fingerprint:
            print("Expected Master recovery SSH fingerprint is required.")
            print("Usage: sudo lattice pairing repair-recovery SHA256:...")
            return 1
        helper = Path("/opt/lattice/bin/lattice-recovery-auth-exec")
        try:
            result = subprocess.run(
                [str(helper), "--adopt-existing", fingerprint],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"Recovery migration could not run: {exc}")
            return 1
        if result.returncode != 0:
            print((result.stderr or result.stdout or "Recovery migration was refused").strip())
            return 1
        print((result.stdout or "Recovery authorization repaired.").strip())
        return 0

    if args.action == "revoke":
        if input("Revoke this master's local credentials now? (y/N): ").strip().lower() != "y":
            print("Cancelled.")
            return 0
        try:
            revoke_local_pairing()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Credentials were not revoked: {exc}")
            return 1
        print("Master credentials revoked. This worker may now enter a new pairing flow.")
        return 0

    print(f"Unknown pairing action: {args.action}")
    return 1
