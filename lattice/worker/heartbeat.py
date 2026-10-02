
import asyncio
import logging
import random
import socket
import ssl
import time
import httpx
import os
from pathlib import Path
from lattice.core.config import load_config
from lattice.onboarding import get_worker_master_endpoint
from lattice.core.worker_auth import read_token_file
from lattice.core.pki import tls_hostname
from lattice.core.service_status import is_service_healthy
from lattice.file_access.sync import (
    FleetSyncError,
    apply_signed_manifest,
    get_cached_fleet_generation,
    get_cached_signed_manifest,
)
from lattice.file_access.transport_queue import (
    FileTransportQueueError,
    queue_transport_reconcile,
)
from lattice.file_access.mount_plan import (
    MountPlanError,
    apply_remote_mount_plan,
)
from lattice.file_access.observations import local_mount_observations
from lattice.backup.observations import (
    backup_service_status, local_backup_observations,
    local_backup_target_observations,
)
from lattice.backup.discovery import local_storage_candidate_payload
from lattice.care.observations import local_care_observation
from lattice.core.lan_routes import local_lan_routes
from lattice.file_access.identity import load_node_identity
from lattice.backup.identity import read_local_backup_identity
from lattice.backup.sync import (
    BackupSyncError,
    apply_signed_backup_assignment,
    ensure_backup_transport_current,
)
from lattice.backup.config_state import (
    BackupConfigStateError,
    applied_config_generation,
    apply_signed_config,
)
from lattice.file_access.applied_state import (
    FILE_APPLIED_PATH, SHELL_APPLIED_PATH, BACKUP_APPLIED_PATH, applied_generation,
    ensure_file_transport_current,
)
from lattice.file_access.home_export import home_bind_is_current
from lattice.file_access.rotation import (
    FileRotationError,
    get_local_rotation_proposal as get_file_rotation_proposal,
    get_promoted_generation as get_file_promoted_generation,
    record_promote_request as record_file_promote_request,
)
from lattice.shell_access.rotation import (
    ShellRotationError,
    get_local_rotation_proposal,
    get_promoted_generation,
    record_promote_request,
)

logger = logging.getLogger(__name__)


# Backoff schedule for heartbeat retries. Each entry is (max_attempts, initial_backoff, max_backoff).
DEFAULT_RETRY = (3, 0.5, 5.0)
# Backoff for "client error" responses — we don't retry those, but log a single line.
CLIENT_ERROR_LOG_EVERY = 60  # seconds


class HeartbeatSender:
    def __init__(self, config, health_checker):
        self.config = config
        self.health_checker = health_checker
        self._running = False
        self.master_ip = config.master.ip
        self.master_port = config.master.api_port  # F131 fix
        self.master_hostname = None
        self.hostname = socket.gethostname()
        self.token_path = f"/etc/lattice/tokens/{self.hostname}.token"
        # Throttle client-error log spam (we don't want to spam every 10s)
        self._last_client_error_log = 0.0
        # Q15 fix: persistent httpx client (avoids new TCP+TLS handshake per send)
        self._client = None  # lazily created in send_heartbeat (needs async)

    async def start(self):
        self._running = True
        logger.info(f"Heartbeat sender started (every 10s, target {self.master_ip}:{self.master_port})")
        while self._running:
            try:
                await self.send_heartbeat()
            except Exception as e:
                # send_heartbeat should never raise, but be defensive.
                logger.error(f"send_heartbeat raised unexpectedly: {e}")
            # Sleep in small chunks so stop() takes effect quickly
            for _ in range(10):
                if not self._running:
                    return
                await asyncio.sleep(1)

    async def stop(self):
        self._running = False
        client = self._client
        self._client = None
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                logger.exception("Could not close worker heartbeat HTTP client cleanly")

    async def send_heartbeat(self):
        # Read token if exists (don't crash if file disappears mid-read)
        token = None
        try:
            if Path(self.token_path).exists():
                token = read_token_file(Path(self.token_path))
        except (OSError, ValueError) as e:
            logger.warning(f"Could not read token at {self.token_path}: {e}")

        try:
            service_statuses = await asyncio.to_thread(
                self.health_checker.check_all
            )
        except Exception as exc:
            logger.error("Health check failed: %s", exc)
            service_statuses = [{"name": "self", "status": "unhealthy"}]

        try:
            fleet_generation = await asyncio.to_thread(
                get_cached_fleet_generation
            )
        except FleetSyncError as exc:
            logger.warning("Could not read cached fleet generation: %s", exc)
            fleet_generation = 0

        try:
            mount_observations = await asyncio.to_thread(local_mount_observations)
        except Exception as exc:
            logger.warning("Could not collect local mount observations: %s", exc)
            mount_observations = []

        try:
            backup_observations = await asyncio.to_thread(local_backup_observations)
        except Exception as exc:
            logger.warning("Could not collect local backup observations: %s", exc)
            backup_observations = []

        try:
            backup_target_observations = await asyncio.to_thread(
                local_backup_target_observations
            )
        except Exception as exc:
            logger.warning("Could not collect local backup target observations: %s", exc)
            backup_target_observations = []

        try:
            care_observation = await asyncio.to_thread(local_care_observation)
        except Exception as exc:
            logger.warning("Could not collect local Daily Care observation: %s", exc)
            care_observation = None

        local_identity = None
        file_transport_generation = 0
        shell_transport_generation = 0
        backup_transport_generation = 0
        backup_config_generation = 0
        file_export_ok = False
        try:
            local_identity = load_node_identity()
            if local_identity is not None:
                if self.config.file_access.enabled:
                    try:
                        # Requeue the already signed/current transport state when
                        # the ephemeral Home bind disappeared after boot/runtime.
                        await asyncio.to_thread(ensure_file_transport_current)
                    except Exception as exc:
                        logger.error(
                            "Could not queue file export self-repair: %s", exc
                        )
                file_transport_generation = applied_generation(
                    FILE_APPLIED_PATH, local_identity.node_id
                )
                shell_transport_generation = applied_generation(
                    SHELL_APPLIED_PATH, local_identity.node_id
                )
                if self.config.file_access.enabled:
                    file_export_ok = await asyncio.to_thread(
                        home_bind_is_current, local_identity
                    )
        except Exception as exc:
            logger.warning("Could not read core applied transport state: %s", exc)

        if local_identity is not None:
            try:
                # Backup bind mounts are ephemeral across reboot. Revalidate
                # the cached signed assignment even when its generation is
                # already current, and queue only a safe same-generation repair.
                await asyncio.to_thread(ensure_backup_transport_current)
            except BackupSyncError as exc:
                logger.error("Backup transport self-repair refused: %s", exc)
            except Exception as exc:
                logger.error("Could not queue backup transport self-repair: %s", exc)
            try:
                backup_transport_generation = applied_generation(
                    BACKUP_APPLIED_PATH, local_identity.node_id
                )
                backup_config_generation = await asyncio.to_thread(
                    applied_config_generation
                )
            except Exception as exc:
                logger.warning("Could not read applied Backup state: %s", exc)

        core_checker = getattr(
            self.health_checker, "check_core_components", None
        )
        if core_checker is not None:
            try:
                core_statuses = await asyncio.to_thread(
                    core_checker,
                    config=self.config,
                    fleet_generation=fleet_generation,
                    file_transport_generation=file_transport_generation,
                    file_export_ok=file_export_ok,
                    shell_transport_generation=shell_transport_generation,
                    mount_observations=mount_observations,
                )
                service_statuses.extend(core_statuses)
                service_statuses.append({
                    "name": "lattice_core",
                    "status": "healthy",
                })
            except Exception as exc:
                logger.error("Core Lattice health evaluation failed: %s", exc)
                service_statuses.append({"name": "lattice_core", "status": "unhealthy"})

        backup_status = backup_service_status(backup_observations)
        if backup_status is not None:
            service_statuses.append({"name": "backup", "status": backup_status})

        healthy = all(
            is_service_healthy(item.get("status"))
            for item in service_statuses
        )
        payload = {
            "worker_id": self.hostname,
            "hostname": self.hostname,
            "timestamp": time.time(),
            "status": "healthy" if healthy else "degraded",
            "services": service_statuses,
            "fleet_generation": fleet_generation,
            "mount_observations": mount_observations,
            "backup_observations": backup_observations,
            "backup_target_observations": backup_target_observations,
            "care_observation": care_observation,
            "file_transport_generation": file_transport_generation,
            "shell_transport_generation": shell_transport_generation,
            "backup_transport_generation": backup_transport_generation,
            "backup_config_generation": backup_config_generation,
        }
        if local_identity is not None:
            try:
                payload["backup_storage_candidates"] = await asyncio.to_thread(
                    local_storage_candidate_payload,
                    local_identity.node_id,
                )
            except Exception as exc:
                logger.warning("Could not inspect local backup storage candidates: %s", exc)
        try:
            backup_identity = await asyncio.to_thread(read_local_backup_identity)
            if backup_identity is not None:
                payload["backup_identity"] = {
                    "node_id": backup_identity.node_id,
                    "public_key": backup_identity.public_key,
                    "host_public_key": backup_identity.host_public_key,
                    "host_key_fingerprint": backup_identity.host_key_fingerprint,
                    "key_generation": backup_identity.key_generation,
                }
        except Exception as exc:
            logger.warning("Could not report backup transport identity: %s", exc)
        try:
            payload["lan_routes"] = await asyncio.to_thread(local_lan_routes)
        except Exception as exc:
            logger.warning("Could not collect local LAN routes: %s", exc)
        try:
            file_rotation_proposal = get_file_rotation_proposal()
            if file_rotation_proposal is not None:
                payload["file_rotation_proposal"] = file_rotation_proposal
            file_promoted_generation = get_file_promoted_generation()
            if file_promoted_generation is not None:
                payload["file_rotation_promoted_generation"] = file_promoted_generation
        except FileRotationError as exc:
            logger.error("Could not report file key rotation state: %s", exc)

        try:
            rotation_proposal = get_local_rotation_proposal()
            if rotation_proposal is not None:
                payload["shell_rotation_proposal"] = rotation_proposal
            promoted_generation = get_promoted_generation()
            if promoted_generation is not None:
                payload["shell_rotation_promoted_generation"] = promoted_generation
        except ShellRotationError as exc:
            logger.error("Could not report shell key rotation state: %s", exc)
        try:
            endpoint = get_worker_master_endpoint()
        except Exception as exc:
            logger.warning(f"Could not read paired master endpoint: {exc}")
            endpoint = None
        if endpoint:
            self.master_ip = endpoint["ip"]
            self.master_port = endpoint["port"]
            self.master_hostname = endpoint.get("hostname")
        ca_path = Path(os.environ.get("LATTICE_PKI_DIR", "/etc/lattice/pki")) / "ca.crt"
        if not ca_path.exists():
            logger.info("Worker is waiting for its secure pairing certificate before heartbeat starts")
            return
        master_host = (
            tls_hostname(self.master_hostname)
            if self.master_hostname else self.master_ip
        )
        primary_url = f"https://{master_host}:{self.master_port}/api/heartbeat"
        fallback_url = f"https://{self.master_ip}:{self.master_port}/api/heartbeat"
        url = primary_url
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        max_attempts, initial_backoff, max_backoff = DEFAULT_RETRY
        backoff = initial_backoff
        for attempt in range(1, max_attempts + 1):
            try:
                if self._client is None:
                    self._client = httpx.AsyncClient(
                        verify=ssl.create_default_context(
                            cafile=str(ca_path)
                        )
                    )
                response = await self._client.post(url, json=payload, headers=headers, timeout=5)
                if response.status_code == 200:
                    # The master may return a newer signed fleet generation.
                    # Verification and disk I/O run outside the asyncio loop.
                    try:
                        response_payload = response.json()
                    except Exception:
                        response_payload = {}

                    if isinstance(response_payload, dict):
                        fleet_update = response_payload.get(
                            "fleet_update"
                        )
                        committed_generation = response_payload.get(
                            "fleet_generation"
                        )

                        effective_fleet_generation = fleet_generation

                        if isinstance(fleet_update, dict):
                            try:
                                applied = await asyncio.to_thread(
                                    apply_signed_manifest,
                                    fleet_update.get(
                                        "manifest"
                                    ),
                                    fleet_update.get(
                                        "signature",
                                        "",
                                    ),
                                )
                                effective_fleet_generation = int(
                                    applied.get(
                                        "generation",
                                        fleet_generation,
                                    )
                                )
                                logger.info(
                                    "Fleet generation %s %s",
                                    effective_fleet_generation,
                                    applied.get(
                                        "status"
                                    ),
                                )
                            except FleetSyncError as exc:
                                # Do not kill heartbeats. Remaining behind
                                # guarantees the master will retry this update.
                                logger.error(
                                    "Rejected fleet update from "
                                    "master: %s",
                                    exc,
                                )

                        # File authorization is reconciled only when the
                        # master confirms this exact generation as committed.
                        if (
                            isinstance(
                                committed_generation,
                                int,
                            )
                            and not isinstance(
                                committed_generation,
                                bool,
                            )
                            and committed_generation > 0
                            and effective_fleet_generation
                            == committed_generation
                        ):
                            try:
                                cached = await asyncio.to_thread(
                                    get_cached_signed_manifest
                                )

                                if cached is not None:
                                    (
                                        committed_manifest,
                                        committed_signature,
                                    ) = cached

                                    local_applied_generation = 0
                                    if local_identity is not None:
                                        local_applied_generation = applied_generation(
                                            FILE_APPLIED_PATH, local_identity.node_id
                                        )
                                    if committed_generation > local_applied_generation:
                                        await asyncio.to_thread(
                                            queue_transport_reconcile,
                                            committed_manifest,
                                            committed_signature,
                                        )
                            except (
                                FleetSyncError,
                                FileTransportQueueError,
                            ) as exc:
                                # The heartbeat itself succeeded. Keep the
                                # cache and retry reconciliation next time.
                                logger.error(
                                    "Could not queue committed fleet "
                                    "transport state: %s",
                                    exc,
                                )

                    if isinstance(response_payload, dict):
                        backup_config = response_payload.get("backup_config")
                        if isinstance(backup_config, dict):
                            try:
                                await asyncio.to_thread(
                                    apply_signed_config,
                                    backup_config.get("config"),
                                    str(backup_config.get("signature", "")),
                                )
                            except BackupConfigStateError as exc:
                                logger.error("Rejected master backup configuration: %s", exc)

                    if isinstance(response_payload, dict):
                        backup_assignment = response_payload.get("backup_assignment")
                        if isinstance(backup_assignment, dict):
                            try:
                                await asyncio.to_thread(
                                    apply_signed_backup_assignment,
                                    backup_assignment.get("assignment"),
                                    str(backup_assignment.get("signature", "")),
                                )
                            except BackupSyncError as exc:
                                logger.error("Rejected master backup assignment: %s", exc)

                    if isinstance(response_payload, dict):
                        file_promote_request = response_payload.get("file_rotation")
                        if isinstance(file_promote_request, dict):
                            try:
                                await asyncio.to_thread(record_file_promote_request, file_promote_request)
                            except FileRotationError as exc:
                                logger.error("Rejected file key promotion request: %s", exc)

                    if isinstance(response_payload, dict):
                        promote_request = response_payload.get("shell_rotation")
                        if isinstance(promote_request, dict):
                            try:
                                await asyncio.to_thread(record_promote_request, promote_request)
                            except ShellRotationError as exc:
                                logger.error("Rejected shell key promotion request: %s", exc)

                    if isinstance(
                        response_payload,
                        dict,
                    ):
                        remote_mount_plan = (
                            response_payload.get(
                                "mount_plan"
                            )
                        )

                        if isinstance(
                            remote_mount_plan,
                            dict,
                        ):
                            try:
                                await asyncio.to_thread(
                                    apply_remote_mount_plan,
                                    remote_mount_plan,
                                )
                            except MountPlanError as exc:
                                # Identity mismatch or stale generation
                                # never affects heartbeat liveness.
                                logger.error(
                                    "Rejected master mount plan: %s",
                                    exc,
                                )

                    if attempt > 1:
                        logger.info(
                            f"Heartbeat succeeded on attempt "
                            f"{attempt}/{max_attempts}"
                        )
                    else:
                        logger.debug(
                            "Heartbeat sent successfully"
                        )
                    return
                # 4xx (other than 408/425/429) is a client error — don't retry
                if 400 <= response.status_code < 500 and response.status_code not in (408, 425, 429):
                    now = time.time()
                    if now - self._last_client_error_log > CLIENT_ERROR_LOG_EVERY:
                        logger.warning(
                            f"Master returned {response.status_code} (client error); "
                            f"not retrying. Body: {response.text[:200]}"
                        )
                        self._last_client_error_log = now
                    return
                # 5xx or retryable 4xx — fall through to retry
                logger.warning(
                    f"Heartbeat server error: {response.status_code}, "
                    f"attempt {attempt}/{max_attempts}"
                )
            except httpx.TimeoutException:
                logger.warning(f"Heartbeat timeout, attempt {attempt}/{max_attempts}")
                if url == primary_url and fallback_url != primary_url:
                    url = fallback_url
                    logger.info("Heartbeat switching to the verified Master IP fallback %s", self.master_ip)
            except (httpx.ConnectError, httpx.NetworkError) as e:
                logger.warning(f"Heartbeat network error: {e}, attempt {attempt}/{max_attempts}")
                if url == primary_url and fallback_url != primary_url:
                    url = fallback_url
                    logger.info("Heartbeat switching to the verified Master IP fallback %s", self.master_ip)
            except Exception as e:
                # Unknown error — don't retry, just log and bail
                logger.error(f"Heartbeat unexpected error: {e}")
                return

            if attempt < max_attempts:
                # Exponential backoff with ±20% jitter
                jitter = random.uniform(-0.2, 0.2)
                await asyncio.sleep(max(0.05, backoff * (1 + jitter)))
                backoff = min(backoff * 2, max_backoff)

        logger.error(f"Heartbeat failed after {max_attempts} attempts to {url}")
