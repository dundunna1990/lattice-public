"""
Health check loop for monitoring workers.

Each worker check is an independent asyncio task. Worker HTTP requests,
SSH reachability probes, healing requests, and recovery waits are asynchronous,
so one failed machine cannot freeze the master event loop.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lattice.core.config import (
    load_config,
    get_config_value,
    set_config_value,
)
from lattice.core.db import get_async_db_connection, is_sqlite_busy_error
from lattice.core.events import (
    log_event,
    resolve_worker_alerts_after_recovery,
)
from lattice.core.http_client import LatticeHTTPClient
from lattice.core.service_status import is_service_failed
from lattice.master.state_machine import (
    update_worker_state,
    WorkerState,
)
from lattice.healing.engine import AutoHealEngine
from lattice.file_access.activation import (
    FleetActivationError,
    reconcile_pending_worker_activation,
)


logger = logging.getLogger(__name__)


class HealthCheckLoop:
    def __init__(self, interval_seconds: int = 10):
        self.interval = interval_seconds
        self._running = False
        self._backoff_state: dict[str, tuple[int, float]] = {}
        self._clients: dict[str, LatticeHTTPClient] = {}

    @staticmethod
    def _backoff_for(failures: int) -> int:
        if failures <= 2:
            return 10
        if failures == 3:
            return 30
        if failures <= 5:
            return 60
        if failures <= 10:
            return 300
        return 1800

    def _record_success(self, hostname: str) -> None:
        if hostname in self._backoff_state:
            logger.debug("Worker %s recovered; clearing backoff state", hostname)
            self._backoff_state.pop(hostname, None)

    def _record_failure(self, hostname: str) -> int:
        import time
        failures, _ = self._backoff_state.get(hostname, (0, 0.0))
        failures += 1
        backoff = self._backoff_for(failures)
        self._backoff_state[hostname] = (failures, time.time() + backoff)
        return backoff

    def _is_in_backoff(self, hostname: str) -> bool:
        import time
        if hostname not in self._backoff_state:
            return False
        _, next_at = self._backoff_state[hostname]
        return time.time() < next_at

    @staticmethod
    async def _has_fresh_service_failure(
        worker_id: int,
        max_age_seconds: int = 60,
    ) -> bool:
        """Return true only for fresh authenticated failed-service evidence."""
        conn = await get_async_db_connection()
        try:
            cursor = await conn.execute(
                """
                SELECT status, last_reported_at
                FROM services
                WHERE worker_id = ?
                  AND last_reported_at IS NOT NULL
                """,
                (worker_id,),
            )
            rows = await cursor.fetchall()
        finally:
            await conn.close()

        now = datetime.now(timezone.utc)
        for row in rows:
            if not is_service_failed(row[0]):
                continue
            try:
                reported_at = datetime.fromisoformat(row[1])
                if reported_at.tzinfo is None:
                    reported_at = reported_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
            age = now - reported_at
            if timedelta(0) <= age <= timedelta(seconds=max_age_seconds):
                return True
        return False

    async def start(self):
        self._running = True
        logger.info(
            "Health check loop started (interval=%ss, per-worker backoff enabled)",
            self.interval,
        )
        while self._running:
            await self._run_checks()
            await asyncio.sleep(self.interval)

    async def _run_checks(self):
        conn = await get_async_db_connection()
        try:
            cursor = await conn.execute(
                """
                SELECT id, hostname, ip, ssh_user, status
                FROM workers
                WHERE removed_at IS NULL
                  AND status != 'disabled'
                """
            )
            workers = await cursor.fetchall()
        finally:
            await conn.close()

        active_hostnames = {worker["hostname"] for worker in workers}
        stale_hostnames = set(self._clients) - active_hostnames
        for hostname in stale_hostnames:
            client = self._clients.pop(hostname, None)
            self._backoff_state.pop(hostname, None)
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    logger.debug(
                        "Failed closing stale client for %s",
                        hostname,
                        exc_info=True,
                    )

        if not workers:
            logger.debug("No workers to check")
            return

        logger.info("Found %s workers to check", len(workers))
        results = await asyncio.gather(
            *(self._check_worker(worker) for worker in workers),
            return_exceptions=True,
        )
        for worker, result in zip(workers, results):
            if isinstance(result, BaseException):
                logger.error(
                    "Unhandled health task failure for %s: %s",
                    worker["hostname"],
                    result,
                    exc_info=(type(result), result, result.__traceback__),
                )

    async def _check_worker(self, worker):
        worker_id = worker["id"]
        hostname = worker["hostname"]
        ip = worker["ip"]
        port = None
        config = await asyncio.to_thread(load_config)

        manual_recheck_key = f"health.recheck.{worker_id}"
        manual_recheck = (
            await asyncio.to_thread(get_config_value, manual_recheck_key)
            == "true"
        )
        if manual_recheck:
            await asyncio.to_thread(set_config_value, manual_recheck_key, "false")

        if self._is_in_backoff(hostname) and not manual_recheck:
            logger.debug("Worker %s in backoff; skipping this tick", hostname)
            return

        logger.debug("Checking worker: %s", hostname)
        try:
            if hostname not in self._clients:
                self._clients[hostname] = LatticeHTTPClient(worker_hostname=hostname)
            client = self._clients[hostname]

            try:
                port = config.wire_format.port
            except AttributeError:
                port = 9999

            response = await client.get(f"http://{ip}:{port}/v1/health", timeout=5.0)
            health_payload = response.json()
            endpoint_status = health_payload.get("status")
            reachable = (
                response.status_code == 200
                and endpoint_status in {"healthy", "degraded"}
            )
            endpoint_degraded = reachable and endpoint_status == "degraded"

            if reachable:
                instance_id = health_payload.get("instance_id")
                if isinstance(instance_id, str) and instance_id:
                    conn = await get_async_db_connection()
                    try:
                        await conn.execute(
                            "UPDATE workers SET last_instance_id = ? WHERE id = ?",
                            (instance_id, worker_id),
                        )
                        await conn.commit()
                    finally:
                        await conn.close()

            logger.debug(
                "Worker %s health: %s",
                hostname,
                "DEGRADED" if endpoint_degraded else ("OK" if reachable else "FAIL"),
            )

            service_degraded = endpoint_degraded
            if reachable:
                service_degraded = service_degraded or (
                    await self._has_fresh_service_failure(worker_id)
                )

            new_state = await asyncio.to_thread(
                update_worker_state,
                worker_id,
                reachable,
                service_degraded=service_degraded,
            )
            logger.info("Worker %s state: %s", hostname, new_state.value)

            if reachable:
                self._record_success(hostname)

                try:
                    conn = await get_async_db_connection()
                    try:
                        cursor = await conn.execute(
                            """SELECT node_id, membership_state
                               FROM fleet_nodes
                               WHERE worker_id=?
                               ORDER BY CASE membership_state
                                   WHEN 'pending' THEN 0
                                   WHEN 'active' THEN 1
                                   ELSE 2 END
                               LIMIT 1""",
                            (worker_id,),
                        )
                        fleet_node = await cursor.fetchone()
                        pending_update = None
                        if (
                            fleet_node is not None
                            and fleet_node["membership_state"] == "pending"
                        ):
                            cursor = await conn.execute(
                                """SELECT generation FROM fleet_pending_updates
                                   WHERE target_node_id=?""",
                                (str(fleet_node["node_id"]),),
                            )
                            pending_update = await cursor.fetchone()
                    finally:
                        await conn.close()

                    if (
                        fleet_node is not None
                        and fleet_node["membership_state"] == "pending"
                    ):
                        from lattice.pairing import repair_worker_network_assignment

                        if pending_update is None:
                            logger.warning(
                                "Pending worker %s has no staged fleet generation; "
                                "retrying trusted activation",
                                hostname,
                            )
                            await asyncio.to_thread(
                                repair_worker_network_assignment,
                                hostname,
                            )
                        else:
                            identity_response = await client.get(
                                f"http://{ip}:{port}/v1/fleet/identity",
                                timeout=5.0,
                            )
                            identity_payload = identity_response.json()
                            if not isinstance(identity_payload, dict):
                                raise FleetActivationError(
                                    "Worker fleet identity response is invalid"
                                )
                            target_node_id = str(fleet_node["node_id"])
                            if identity_payload.get("node_id") != target_node_id:
                                raise FleetActivationError(
                                    "Authenticated worker identity does not match "
                                    "pending fleet node"
                                )
                            reported_generation = identity_payload.get(
                                "fleet_generation"
                            )

                            def _reconcile_activation() -> str:
                                from lattice.core.db import get_db_connection
                                sync_conn = get_db_connection()
                                try:
                                    outcome = reconcile_pending_worker_activation(
                                        sync_conn,
                                        target_node_id=target_node_id,
                                        reported_generation=reported_generation,
                                    )
                                    sync_conn.commit()
                                    return outcome
                                except Exception:
                                    sync_conn.rollback()
                                    raise
                                finally:
                                    sync_conn.close()

                            outcome = await asyncio.to_thread(
                                _reconcile_activation
                            )
                            if outcome == "committed":
                                from lattice.pairing import (
                                    reconcile_committed_worker_activation,
                                )
                                await asyncio.to_thread(
                                    reconcile_committed_worker_activation,
                                    hostname,
                                    worker_ip=ip,
                                )
                                logger.warning(
                                    "Recovered interrupted fleet activation for %s "
                                    "from worker-confirmed generation %s",
                                    hostname,
                                    reported_generation,
                                )
                                await asyncio.to_thread(
                                    log_event,
                                    worker_id,
                                    "fleet.activation_recovered",
                                    "ok",
                                    (
                                        f"Recovered interrupted fleet activation for "
                                        f"{hostname} at generation "
                                        f"{reported_generation}"
                                    ),
                                )
                            elif outcome == "discarded":
                                logger.warning(
                                    "Worker %s did not apply staged generation %s; "
                                    "retrying trusted activation",
                                    hostname,
                                    pending_update["generation"],
                                )
                                await asyncio.to_thread(
                                    log_event,
                                    worker_id,
                                    "fleet.activation_retryable",
                                    "warn",
                                    (
                                        f"Worker {hostname} did not apply its staged "
                                        "fleet generation; Lattice safely cleared it "
                                        "and is retrying activation"
                                    ),
                                )
                                await asyncio.to_thread(
                                    repair_worker_network_assignment,
                                    hostname,
                                )

                    elif (
                        fleet_node is not None
                        and fleet_node["membership_state"] == "active"
                        and worker["status"] == "configuring"
                    ):
                        from lattice.pairing import (
                            reconcile_committed_worker_activation,
                        )
                        await asyncio.to_thread(
                            reconcile_committed_worker_activation,
                            hostname,
                            worker_ip=ip,
                        )
                        logger.warning(
                            "Finished Master-local reconciliation for previously "
                            "committed worker %s",
                            hostname,
                        )
                except FleetActivationError as exc:
                    logger.error(
                        "Interrupted activation for %s could not be reconciled "
                        "safely: %s",
                        hostname,
                        exc,
                    )
                except Exception as exc:
                    logger.warning(
                        "Could not reconcile interrupted activation for %s: %s",
                        hostname,
                        exc,
                    )

            severity = "warn" if service_degraded else ("ok" if reachable else "error")
            detail = "degraded" if service_degraded else ("healthy" if reachable else "failed")
            await asyncio.to_thread(
                log_event,
                worker_id,
                "health_check",
                severity,
                f"Health check for {hostname}: {detail}",
            )

            if new_state == WorkerState.HEALTHY:
                resolved = await asyncio.to_thread(
                    resolve_worker_alerts_after_recovery,
                    worker_id,
                )
                if resolved:
                    logger.info(
                        "Verified recovery resolved %s alert(s) for %s",
                        resolved,
                        hostname,
                    )

            if new_state == WorkerState.DOWN:
                await self._evaluate_repair(worker_id, ip)

        except Exception as exc:
            if is_sqlite_busy_error(exc):
                logger.warning(
                    "Master database busy while recording health for %s; "
                    "preserving Worker state and retrying next cycle",
                    hostname,
                )
                return

            port_str = f":{port}" if port else ""
            logger.error(
                "Worker %s (%s%s) health check failed: %s",
                hostname,
                ip,
                port_str,
                exc,
            )
            if hasattr(exc, "response") and exc.response is not None:
                logger.error(
                    "Status: %s, Body: %s",
                    exc.response.status_code,
                    exc.response.text[:200],
                )

            await asyncio.to_thread(
                log_event,
                worker_id,
                "health_check",
                "error",
                f"Health check failed for {hostname}: {exc}",
            )
            backoff = self._record_failure(hostname)
            logger.info(
                "Worker %s now in %ss backoff due to failure",
                hostname,
                backoff,
            )

            try:
                new_state = await asyncio.to_thread(
                    update_worker_state,
                    worker_id,
                    False,
                )
                logger.info(
                    "Worker %s state (after error): %s",
                    hostname,
                    new_state.value,
                )
                if new_state == WorkerState.DOWN:
                    await self._evaluate_repair(worker_id, ip)
            except Exception as state_exc:
                logger.error("Failed to update state for %s: %s", hostname, state_exc)

    @staticmethod
    async def _evaluate_repair(worker_id: int, ip: str) -> None:
        """Evaluate repair without blocking the master event loop."""
        engine = AutoHealEngine()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=3,
            )
            del reader
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (OSError, asyncio.TimeoutError):
            await asyncio.to_thread(
                engine.report_protected_issue,
                worker_id,
                "SSH",
                "the worker is down and SSH port 22 is not reachable",
            )
            return

        await asyncio.to_thread(
            log_event,
            worker_id,
            "ssh_probe.worker_api_down",
            "error",
            "Worker machine answered on SSH while its Lattice API was down",
        )
        logger.info(
            "Self-healing policy evaluating lattice-worker on worker %s",
            worker_id,
        )
        await engine.attempt_heal(
            worker_id,
            "lattice-worker",
            "restart",
            {
                "type": "systemd",
                "reason": "worker health endpoint is unreachable",
            },
        )

    def stop(self):
        self._running = False
        for client in self._clients.values():
            try:
                client.close()
            except Exception:
                pass
        self._clients.clear()
        logger.info("Health check loop stopped")
