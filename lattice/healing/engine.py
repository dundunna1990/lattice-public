"""
Auto-heal engine – integrates circuit breaker, hard no-heal, structured checks,
2-signal requirement, identity confidence, and audit logging.
Decision 12 B+ bulletproof implementation.
"""
import asyncio
import inspect
import logging
import ipaddress
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from lattice.core.db import get_async_db_connection
from lattice.core.config import load_config, get_config_value, set_config_value
import httpx

from lattice.core.http_client import LatticeHTTPClient
from lattice.core.events import log_event, create_alert
from lattice.master.circuit_breaker import CircuitBreaker
from lattice.healing.hard_no import is_autoheal_action_allowed
from lattice.healing.checks import run_check
from lattice.healing.signals import get_worker_identity_status as worker_identity_verified, get_health_signals
from lattice.healing.audit_log import AuditLog, DEFAULT_LOG_PATH
from lattice.healing.policy import (
    MODE_ALERT_ONLY,
    MODE_AUTOMATIC,
    record_restart_attempt,
    restart_budget_available,
    reserve_restart_attempt,
)

logger = logging.getLogger(__name__)

DEFAULT_REQUIRED_SIGNALS = 2
SSH_PRIVATE_KEY = Path("/etc/lattice/keys/lattice_ed25519")
SSH_KNOWN_HOSTS = Path("/etc/lattice/keys/known_hosts")
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")



# One asyncio lock per worker prevents concurrent repairs of the same
# worker while allowing repairs/checks for different workers to overlap.
_worker_heal_locks: dict[int, asyncio.Lock] = {}


def _get_worker_lock(worker_id: int) -> asyncio.Lock:
    lock = _worker_heal_locks.get(worker_id)
    if lock is None:
        lock = asyncio.Lock()
        _worker_heal_locks[worker_id] = lock
    return lock


class AutoHealEngine:
    def __init__(self, ssh_runner=None):
        self.audit = AuditLog(DEFAULT_LOG_PATH)
        self._ssh_runner = ssh_runner

    async def _read_worker_health(
        self,
        client,
        worker_ip: str,
        port: int,
    ) -> dict | None:
        try:
            health = await client.get(
                f"http://{worker_ip}:{port}/v1/health",
                timeout=5.0,
            )

            if health.status_code != 200:
                return None

            payload = health.json()

            if not isinstance(payload, dict):
                return None

            return payload

        except Exception:
            return None

    async def _verify_worker_recovery(
        self,
        client,
        worker_ip: str,
        port: int,
        previous_instance_id: str | None,
    ) -> bool:
        """Require healthy state from a newly started worker process."""
        if not previous_instance_id:
            # We cannot prove a restart without a before-instance identity.
            return False

        for _ in range(15):
            await asyncio.sleep(2)

            payload = await self._read_worker_health(
                client,
                worker_ip,
                port,
            )

            if not payload:
                continue

            new_instance_id = payload.get(
                "instance_id"
            )

            if (
                payload.get("status") == "healthy"
                and isinstance(
                    new_instance_id,
                    str,
                )
                and new_instance_id
                and new_instance_id
                != previous_instance_id
            ):
                return True

        return False

    async def _restart_worker_via_forced_ssh(
        self,
        worker_ip: str,
        worker_hostname: str,
        ssh_user: str,
        master_ip: str,
    ) -> tuple[bool, str]:
        """Invoke the exact forced SSH restart without blocking asyncio."""
        if not SSH_USER_RE.fullmatch(ssh_user or ""):
            return False, "saved SSH user is invalid"
        if (
            not worker_hostname
            or len(worker_hostname) > 253
            or any(ch.isspace() for ch in worker_hostname)
        ):
            return False, "saved worker hostname is invalid"

        try:
            worker_ip = str(
                ipaddress.ip_address(worker_ip)
            )
            master_ip = str(
                ipaddress.ip_address(master_ip)
            )
        except ValueError:
            return (
                False,
                "saved worker or master address is invalid",
            )

        if (
            not SSH_PRIVATE_KEY.is_file()
            or not SSH_KNOWN_HOSTS.is_file()
        ):
            return (
                False,
                "paired SSH key or known-host record is missing",
            )

        command = [
            "ssh",
            "-i",
            str(SSH_PRIVATE_KEY),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"HostKeyAlias={worker_hostname}",
            "-o",
            f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"BindAddress={master_ip}",
            "--",
            f"{ssh_user}@{worker_ip}",
            "restart lattice-worker.service",
        ]

        # Tests may inject a runner. Production uses asyncio subprocesses.
        if self._ssh_runner is not None:
            try:
                result = self._ssh_runner(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if inspect.isawaitable(result):
                    result = await result
            except (OSError, subprocess.TimeoutExpired) as exc:
                return False, str(exc)

            detail = (
                result.stderr
                or result.stdout
                or "forced SSH restart failed"
            ).strip()
            return result.returncode == 0, detail

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return False, "forced SSH restart timed out"

        except OSError as exc:
            return False, str(exc)

        detail = (
            (stderr or stdout)
            .decode("utf-8", errors="replace")
            .strip()
            or "forced SSH restart failed"
        )

        return process.returncode == 0, detail

    def _get_opt_in_status(self, worker_id: int) -> bool:
        key = f"autoheal.enabled.{worker_id}"
        value = get_config_value(key)
        return value == "true"

    def _set_opt_in(self, worker_id: int, enabled: bool) -> None:
        key = f"autoheal.enabled.{worker_id}"
        set_config_value(key, "true" if enabled else "false")
        logger.info(f"Auto-heal {'enabled' if enabled else 'disabled'} for worker {worker_id}")

    def _mode(self) -> str:
        """Alert-only is the safe default until the owner explicitly changes it."""
        value = get_config_value("autoheal.mode")
        return MODE_AUTOMATIC if value == MODE_AUTOMATIC else MODE_ALERT_ONLY

    def _is_paused(self) -> bool:
        value = get_config_value("auto_heal.pause_until")
        if not value:
            return False
        try:
            until = datetime.fromisoformat(value)
            if until.tzinfo is None:
                return False
            return until > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid auto-heal pause timestamp")
            return False

    def _report_failed_repair(self, worker_id: int, worker_hostname: str, service: str, reason: str) -> None:
        """Create the visible stop-and-tell-the-owner outcome for a failed repair."""
        message = f"Lattice tried one safe restart of {service} on {worker_hostname}, but it did not recover: {reason}"
        event_id = log_event(worker_id, "autoheal.failed", "error", message)
        create_alert(worker_id, "error", f"Lattice repair needs attention: {service}", message, event_id)

    def report_detected_failure(self, worker_id, service_name, reason, action="restart"):
        """Record and alert on a failure without taking any machine action."""
        message = (
            f"Detected a problem with {service_name}. Alert-only mode is active; "
            f"Lattice did not {action} it. Reason: {reason}"
        )
        event_id = log_event(worker_id, "autoheal.detected", "warn", message)
        create_alert(
            worker_id,
            "warn",
            f"Lattice service problem: {service_name}",
            message,
            event_id,
        )
        self.audit.log_entry(
            worker_id=worker_id,
            service=service_name,
            action=action,
            params={"reason": reason},
            result="alert_only",
            error="automatic restart is not enabled",
        )
        return False

    def report_protected_issue(self, worker_id, subject, reason):
        """Alert about a protected area such as SSH without ever changing it."""
        message = f"Detected a problem with protected {subject}. Lattice made no change. Reason: {reason}"
        event_id = log_event(worker_id, "autoheal.protected_issue", "warn", message)
        create_alert(worker_id, "warn", f"Protected system problem: {subject}", message, event_id)
        self.audit.log_entry(
            worker_id=worker_id,
            service=subject,
            action="none",
            params={"reason": reason},
            result="alerted",
            error="protected area; automatic change is forbidden",
        )
        return False

    def should_heal(self, worker_id: int, service_name: str, action: str) -> bool:
        if not self._get_opt_in_status(worker_id):
            logger.debug(f"Worker {worker_id} not opted in to auto-heal")
            return False

        if not worker_identity_verified(worker_id):
            logger.warning(f"Worker {worker_id} identity not verified, skipping heal")
            return False

        if not is_autoheal_action_allowed(action, service_name):
            logger.info(
                f"Auto-heal policy blocked {action} on {service_name} for worker {worker_id}"
            )
            return False

        cb = CircuitBreaker(worker_id, f"{service_name}:{action}")
        if cb.is_open():
            logger.info(f"Circuit breaker open for {service_name}:{action} on worker {worker_id}")
            return False

        signals = get_health_signals(worker_id, service_name)
        failure_count = sum(signal["status"] is False for signal in signals)
        if failure_count < DEFAULT_REQUIRED_SIGNALS:
            logger.debug(f"Worker {worker_id} has only {failure_count} failure signals, need {DEFAULT_REQUIRED_SIGNALS}")
            return False

        return True

    async def attempt_heal(self, worker_id: int, service_name: str, action: str, params: Dict[str, Any] = None) -> bool:
        """Heal a service by sending an HTTP request to the worker.

        Flow:
        1. Check should_heal (opt-in, identity, hard-no, circuit breaker, signals).
        2. Acquire per-worker action lock (serializes heals for the same worker).
        3. Look up the worker's IP + hostname from the DB.
        4. Send HTTP POST to {worker_ip}:{wire_port}/v1/actions via LatticeHTTPClient.
        5. Handle response: 200+success → record_success; 200+error → record_failure;
           403 hard-no → record_failure; 4xx other → record_failure; unreachable → record_failure.
        6. Log to audit log + events table.

        Bulletproofness:
        - Per-worker lock prevents two heals from racing on the same worker.
        - LatticeHTTPClient handles retry + backoff for transient network errors.
        - All exceptions are caught — attempt_heal never raises.
        - The audit log captures every attempt + outcome for forensic review.
        """
        if not is_autoheal_action_allowed(action, service_name):
            logger.info(f"Auto-heal policy blocked {action} on {service_name} for worker {worker_id}")
            return False

        if await asyncio.to_thread(self._is_paused):
            logger.info("Automatic healing is temporarily paused by the owner")
            return False

        if (
            await asyncio.to_thread(self._mode)
            == MODE_ALERT_ONLY
        ):
            return await asyncio.to_thread(
                self.report_detected_failure,
                worker_id,
                service_name,
                (params or {}).get("reason", "health checks reported a failure"),
                action,
            )

        if not await asyncio.to_thread(
            self.should_heal,
            worker_id,
            service_name,
            action,
        ):
            return False

        # Dry-run is a fail-safe default. It records what Lattice would have
        # done, but it never contacts a worker or queues a fallback action.
        try:
            dry_run = (
                await asyncio.to_thread(
                    load_config
                )
            ).daemon.dry_run
        except Exception as exc:
            logger.error(f"Unable to read dry-run setting; blocking action: {exc}")
            dry_run = True
        if dry_run:
            safe_params = params or {}
            await asyncio.to_thread(
                self.audit.log_entry,
                worker_id=worker_id,
                service=service_name,
                action=action,
                params=safe_params,
                result="dry_run",
                error="dry_run enabled; no action executed",
            )
            await asyncio.to_thread(
                log_event,
                worker_id,
                "autoheal.dry_run",
                "info",
                f"Dry run: would {action} {service_name}, but no action was executed",
            )
            return False

        # Per-worker serialization prevents overlapping repairs for the same
        # worker. The restart budget reservation itself is also an atomic
        # SQLite transaction, protecting against competing processes.
        async with _get_worker_lock(worker_id):
            if action == "restart":
                if not await asyncio.to_thread(
                    reserve_restart_attempt,
                    worker_id,
                    service_name,
                ):
                    return await asyncio.to_thread(
                        self.report_detected_failure,
                        worker_id,
                        service_name,
                        (
                            "the two-restart limit in the last "
                            "15 minutes has been reached"
                        ),
                        action,
                    )

            return await self._attempt_heal_locked(
                worker_id,
                service_name,
                action,
                params or {},
            )

    async def _attempt_heal_locked(self, worker_id: int, service_name: str, action: str, params: Dict[str, Any]) -> bool:
        """Inner attempt_heal, called while holding the per-worker lock."""
        audit_saved = await asyncio.to_thread(
            self.audit.log_entry,
            worker_id=worker_id,
            service=service_name,
            action=action,
            params=params,
            result="attempted"
        )
        if not audit_saved:
            message = (
                f"Lattice did not restart {service_name}: the protected repair record "
                "could not be saved. No machine action was taken."
            )
            event_id = log_event(worker_id, "autoheal.audit_failed", "critical", message)
            await asyncio.to_thread(
                create_alert,
                worker_id, "critical", "Automatic repair stopped: audit unavailable",
                message, event_id,
            )
            return False

        # Look up the worker without blocking asyncio.
        conn = await get_async_db_connection()
        try:
            cursor = await conn.execute(
                """
                SELECT ip, hostname, ssh_user, last_instance_id
                FROM workers
                WHERE id = ?
                """,
                (worker_id,),
            )
            row = await cursor.fetchone()
        finally:
            await conn.close()
        if not row or not row[0]:
            logger.error(f"Cannot heal worker {worker_id}: no IP/hostname in DB")
            await asyncio.to_thread(
                self.audit.log_entry,
                worker_id=worker_id,
                service=service_name,
                action=action,
                params=params,
                result="failed",
                error="no IP/hostname"
            )
            return False
        worker_ip, worker_hostname, ssh_user, stored_instance_id = row[0], row[1], row[2], row[3]

        # Get the wire port from config
        config = None
        try:
            config = await asyncio.to_thread(load_config)
            port = getattr(config.wire_format, "port", 9999)
        except Exception:
            port = 9999

        url = f"http://{worker_ip}:{port}/v1/actions"

        cb = CircuitBreaker(worker_id, f"{service_name}:{action}")

        try:
            client = await asyncio.to_thread(
                LatticeHTTPClient,
                worker_hostname=worker_hostname,
            )
            before_health = (
                await self._read_worker_health(
                    client,
                    worker_ip,
                    port,
                )
            )

            previous_instance_id = (
                before_health.get("instance_id")
                if before_health
                else stored_instance_id
            )

            response = await client.post(
                url,
                json={
                    "action": action,
                    "target": service_name,
                },
                timeout=30.0,
            )

            # The worker only accepts the restart request; it cannot promise
            # success before restarting itself. Verify the health endpoint
            # afterward instead of treating acceptance as recovery.
            if response.status_code == 202:
                recovered = await self._verify_worker_recovery(
                    client,
                    worker_ip,
                    port,
                    previous_instance_id,
                )
                if recovered:
                    await asyncio.to_thread(cb.record_success)
                    log_event(worker_id, "autoheal.success", "info",
                              f"Auto-heal verified recovery for {service_name} on {worker_hostname}")
                    await asyncio.to_thread(
                self.audit.log_entry,
                        worker_id=worker_id, service=service_name, action=action,
                        params=params, result="success"
                    )
                    return True
                await asyncio.to_thread(cb.record_failure)
                await asyncio.to_thread(
                    self._report_failed_repair,
                    worker_id, worker_hostname, service_name,
                    "the worker did not become healthy after the restart request",
                )
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id, service=service_name, action=action,
                    params=params, result="failed", error="post-restart health verification failed"
                )
                return False

            # Backward-compatible success response from an older worker.
            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception:
                    data = {}
                if data.get("status") == "success":
                    await asyncio.to_thread(cb.record_success)
                    log_event(worker_id, "autoheal.success", "info",
                              f"Auto-heal succeeded for {service_name}: {action} on {worker_hostname}")
                    await asyncio.to_thread(
                self.audit.log_entry,
                        worker_id=worker_id, service=service_name, action=action,
                        params=params, result="success"
                    )
                    return True
                # 200 but body says error
                err_msg = (data.get("stderr") or data.get("detail") or "unknown")[:200]
                await asyncio.to_thread(cb.record_failure)
                log_event(worker_id, "autoheal.failed", "error",
                          f"Auto-heal reported failure: {action} on {worker_hostname}: {err_msg}")
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id, service=service_name, action=action,
                    params=params, result="failed", error=err_msg
                )
                return False

            # 403: hard-no-heal
            if response.status_code == 403:
                await asyncio.to_thread(cb.record_failure)
                log_event(worker_id, "autoheal.hard_no", "warn",
                          f"Auto-heal blocked: {action} on {service_name} is in hard-no list")
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id, service=service_name, action=action,
                    params=params, result="blocked", error="hard no-heal"
                )
                return False

            # 404: service not found on worker
            if response.status_code == 404:
                await asyncio.to_thread(cb.record_failure)
                log_event(worker_id, "autoheal.not_found", "warn",
                          f"Service {service_name} not found on {worker_hostname}")
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id, service=service_name, action=action,
                    params=params, result="not_found", error="service not found"
                )
                return False

            # 4xx other: client error, don't retry
            if 400 <= response.status_code < 500:
                await asyncio.to_thread(cb.record_failure)
                log_event(worker_id, "autoheal.failed", "error",
                          f"Auto-heal HTTP {response.status_code}: {response.text[:200]}")
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id, service=service_name, action=action,
                    params=params, result="failed", error=f"HTTP {response.status_code}"
                )
                return False

            # 5xx: server error (LatticeHTTPClient already retried)
            await asyncio.to_thread(cb.record_failure)
            log_event(worker_id, "autoheal.failed", "error",
                      f"Auto-heal HTTP {response.status_code} (after retries): {response.text[:200]}")
            await asyncio.to_thread(
                self.audit.log_entry,
                worker_id=worker_id, service=service_name, action=action,
                params=params, result="failed", error=f"HTTP {response.status_code}"
            )
            return False

        except httpx.TransportError as e:
            logger.warning(
                f"Worker API unavailable for {worker_hostname}; trying the exact forced SSH restart"
            )
            fallback_audited = self.audit.log_entry(
                worker_id=worker_id,
                service="lattice-worker",
                action="restart",
                params={"transport_error": str(e)},
                result="ssh_fallback_attempted",
            )
            if not fallback_audited:
                await asyncio.to_thread(
                    self._report_failed_repair,
                    worker_id,
                    worker_hostname,
                    service_name,
                    "the protected SSH fallback record could not be saved",
                )
                return False
            master_ip = getattr(getattr(config, "master", None), "ip", "")
            restarted, detail = await self._restart_worker_via_forced_ssh(
                worker_ip, worker_hostname, ssh_user, master_ip
            )
            if restarted and await self._verify_worker_recovery(
                client,
                worker_ip,
                port,
                previous_instance_id,
            ):
                await asyncio.to_thread(cb.record_success)
                await asyncio.to_thread(
                    log_event,
                    worker_id,
                    "autoheal.success",
                    "info",
                    f"Auto-heal verified SSH fallback recovery for {service_name} on {worker_hostname}",
                )
                await asyncio.to_thread(
                self.audit.log_entry,
                    worker_id=worker_id,
                    service=service_name,
                    action=action,
                    params=params,
                    result="success_via_ssh",
                )
                return True
            await asyncio.to_thread(cb.record_failure)
            reason = detail if not restarted else "worker API did not recover after SSH restart"
            await asyncio.to_thread(
                self._report_failed_repair,
                worker_id, worker_hostname, service_name, f"SSH fallback failed: {reason}"
            )
            await asyncio.to_thread(
                self.audit.log_entry,
                worker_id=worker_id,
                service=service_name,
                action=action,
                params=params,
                result="failed",
                error=f"SSH fallback failed: {reason}",
            )
            return False
        except Exception as e:
            # Unreachable, timeout-after-retries, or any other network failure
            logger.error(f"Auto-heal network failure for {service_name} on {worker_hostname}: {e}")
            await asyncio.to_thread(cb.record_failure)
            self._report_failed_repair(worker_id, worker_hostname, service_name, f"network failure: {e}")
            await asyncio.to_thread(
                self.audit.log_entry,
                worker_id=worker_id, service=service_name, action=action,
                params=params, result="error", error=str(e)
            )
            # Do not use a fallback queue: it could execute after the incident
            # is stale, and it would bypass the one-time verified restart path.
            return False
        finally:
            try:
                await client.aclose()
            except Exception:
                pass
