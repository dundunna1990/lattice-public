import logging
import os
import subprocess

from lattice.core.db import get_db_connection
from lattice.core.service_status import is_service_healthy

logger = logging.getLogger(__name__)


class HealthChecker:
    def __init__(self):
        self.services = []

    def check_all(self):
        sshd_check = self.check_sshd()
        results = [{
            "name": "sshd",
            "status": "healthy" if sshd_check else "unhealthy",
        }]
        try:
            from lattice.ip_change.reconcile import read_network_health
            network = read_network_health()
        except Exception as exc:
            logger.error("network health check failed: %s", exc)
            network = {"name": "network", "status": "unhealthy"}
        if network is not None:
            results.append(network)
        return results

    def current_snapshot(self) -> dict:
        """Return one read-only health snapshot used by the live API.

        This deliberately reuses the same component checks used by heartbeat
        reporting. It observes current state only; it never queues repair work.
        """
        from lattice.core.config import load_config
        from lattice.file_access.applied_state import (
            FILE_APPLIED_PATH,
            SHELL_APPLIED_PATH,
            applied_generation,
        )
        from lattice.file_access.home_export import home_bind_is_current
        from lattice.file_access.identity import load_node_identity
        from lattice.file_access.observations import local_mount_observations
        from lattice.file_access.sync import FleetSyncError, get_cached_fleet_generation
        from lattice.backup.observations import (
            backup_service_status,
            local_backup_observations,
        )

        config = load_config()
        statuses = self.check_all()

        try:
            fleet_generation = get_cached_fleet_generation()
        except FleetSyncError as exc:
            logger.warning("Could not read cached fleet generation: %s", exc)
            fleet_generation = 0

        try:
            mount_observations = local_mount_observations()
        except Exception as exc:
            logger.warning("Could not collect local mount observations: %s", exc)
            mount_observations = []

        try:
            backup_observations = local_backup_observations()
        except Exception as exc:
            logger.warning("Could not collect local backup observations: %s", exc)
            backup_observations = []

        file_transport_generation = 0
        shell_transport_generation = 0
        file_export_ok = False
        try:
            identity = load_node_identity()
            if identity is not None:
                file_transport_generation = applied_generation(
                    FILE_APPLIED_PATH, identity.node_id
                )
                shell_transport_generation = applied_generation(
                    SHELL_APPLIED_PATH, identity.node_id
                )
                if config.file_access.enabled:
                    file_export_ok = home_bind_is_current(identity)
        except Exception as exc:
            logger.warning("Could not read applied transport state: %s", exc)

        try:
            statuses.extend(self.check_core_components(
                config=config,
                fleet_generation=fleet_generation,
                file_transport_generation=file_transport_generation,
                file_export_ok=file_export_ok,
                shell_transport_generation=shell_transport_generation,
                mount_observations=mount_observations,
            ))
            statuses.append({"name": "lattice_core", "status": "healthy"})
        except Exception as exc:
            logger.exception("Core Lattice health evaluation failed: %s", exc)
            statuses.append({"name": "lattice_core", "status": "unhealthy"})

        backup_status = backup_service_status(backup_observations)
        if backup_status is not None:
            statuses.append({"name": "backup", "status": backup_status})

        healthy = all(
            is_service_healthy(item.get("status"))
            for item in statuses
        )
        return {
            "status": "healthy" if healthy else "degraded",
            "services": statuses,
            "fleet_generation": fleet_generation,
            "file_transport_generation": file_transport_generation,
            "shell_transport_generation": shell_transport_generation,
            "mount_observations": mount_observations,
        }

    def check_core_components(
        self,
        *,
        config,
        fleet_generation: int,
        file_transport_generation: int,
        file_export_ok: bool,
        shell_transport_generation: int,
        mount_observations: list[dict],
    ) -> list[dict]:
        results = []
        fleet_ok = fleet_generation > 0
        results.append({
            "name": "fleet_sync",
            "status": "healthy" if fleet_ok else "unhealthy",
        })

        if config.file_access.enabled:
            file_ok = fleet_ok and file_transport_generation == fleet_generation
            results.append({
                "name": "file_transport",
                "status": "healthy" if file_ok else "unhealthy",
            })
            results.append({
                "name": "file_export",
                "status": "healthy" if file_export_ok else "unhealthy",
            })

            required_mounts = [
                row for row in mount_observations
                if row.get("state") != "paused"
            ]
            mounts_ok = bool(mount_observations) and all(
                row.get("state") in {"mounted", "paused"}
                for row in mount_observations
            )
            if not required_mounts and mount_observations:
                mounts_ok = True
            results.append({
                "name": "mounts",
                "status": "healthy" if mounts_ok else "unhealthy",
            })
        if config.shell_access.enabled:
            shell_daemon_ok = self.check_systemd_unit("lattice-shell-sshd.service")
            shell_transport_ok = (
                fleet_ok
                and shell_transport_generation == fleet_generation
                and shell_daemon_ok
            )
            results.append({
                "name": "shell_transport",
                "status": "healthy" if shell_transport_ok else "unhealthy",
            })

            conn = get_db_connection()
            try:
                rows = conn.execute(
                    "SELECT state FROM shell_connection_state "
                    "WHERE state != 'retired' ORDER BY peer_node_id LIMIT 64"
                ).fetchall()
            finally:
                conn.close()
            shell_ok = bool(rows) and all(
                row["state"] == "connected" for row in rows
            )
            results.append({
                "name": "trusted_shell",
                "status": "healthy" if shell_ok else "unhealthy",
            })

        return results

    def check_systemd_unit(self, unit: str) -> bool:
        try:
            child_env = os.environ.copy()
            child_env.pop("NOTIFY_SOCKET", None)
            result = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=30, env=child_env,
            )
            return result.returncode == 0 and result.stdout.strip() == "active"
        except Exception as exc:
            logger.error("systemd health check failed for %s: %s", unit, exc)
            return False

    def check_sshd(self):
        try:
            for unit in ("ssh", "sshd"):
                child_env = os.environ.copy()
                child_env.pop("NOTIFY_SOCKET", None)
                result = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=child_env,
                )
                if result.returncode == 0 and result.stdout.strip() == "active":
                    return True
            return False
        except Exception as exc:
            logger.error("sshd health check failed: %s", exc)
            return False
