"""Refresh the Master node's local Backup observations at heartbeat-like cadence."""
from datetime import datetime, timezone

from lattice.backup.alerts import refresh_local_master_observations


def main() -> None:
    refresh_local_master_observations(datetime.now(timezone.utc).isoformat())


if __name__ == "__main__":
    main()
