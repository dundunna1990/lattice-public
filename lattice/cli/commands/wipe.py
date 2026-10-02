import sys
import logging

logger = logging.getLogger(__name__)
from lattice.core.db import get_db_connection
from lattice.core.config import load_config
import hmac

def perform_wipe(*, output=print) -> int:
    """Revoke every active Worker, then clear Master fleet state.

    Authentication and confirmation belong to the calling interface.  This
    function is the one shared destructive operation used by both CLI and TUI.
    """
    try:
        from lattice.wizard.lifecycle import current_role
        role = current_role()
    except Exception:
        role = None
    if role != "master":
        output("REFUSED: Fleet reset is available only on the Lattice Master.")
        return 1
    output("Wiping everything...")
    conn = get_db_connection()
    try:
        hostnames = [row[0] for row in conn.execute(
            "SELECT hostname FROM workers WHERE removed_at IS NULL ORDER BY hostname"
        ).fetchall()]
    finally:
        conn.close()
    from lattice.cli.commands.workers import remove_worker_safely
    for hostname in hostnames:
        output(f"Cleaning credentials from {hostname}...")
        if remove_worker_safely(hostname, ask_confirmation=False, output=output) != 0:
            output(f"❌ Wipe stopped safely. {hostname} still has Lattice credentials.")
            return 1
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Clear every current fleet/runtime table in foreign-key-safe order.
        # Machine identity and host-restoration files are intentionally outside
        # this database reset; Reset Lattice is not an uninstall.
        tables = (
            "mount_observations",
            "shares",
            "fleet_pending_updates",
            "shell_key_rotations",
            "file_key_rotations",
            "peer_routes",
            "shell_connection_history",
            "shell_connection_state",
            "mount_state",
            "mount_preferences",
            "fleet_settings",
            "fleet_state",
            "services",
            "alerts",
            "events",
            "circuit_breaker_state",
            "healing_attempts",
            "fleet_nodes",
            "config",
            "workers",
        )
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        conn.commit()
        output("✅ Every worker was revoked and all Lattice state was removed.")
        return 0
    except Exception as e:
        conn.rollback()
        output(f"❌ Error: {e}")
        return 1
    finally:
        conn.close()

def cmd_wipe(args):
    logger.info("Command cmd_wipe called")
    # Keep CLI authentication exactly as strong as before, then call the same
    # destructive operation that the curses TUI uses.
    try:
        config = load_config()
        master_key = config.master.master_key
        if not master_key:
            print("No master key set. Please set one in config first.")
            return 1
        import getpass
        entered = getpass.getpass("Enter master key: ")
        if not hmac.compare_digest(entered, master_key):
            print("Invalid master key.")
            return 1
        confirm = input("Type 'WIPE' to confirm: ").strip()
        if confirm != "WIPE":
            print("Cancelled.")
            return 0
    except Exception as e:
        print(f"Error during authentication: {e}")
        return 1
    return perform_wipe()
