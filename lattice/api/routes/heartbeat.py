import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from lattice.core.db import get_async_db_connection, is_sqlite_busy_error
from lattice.core.events import log_event, sync_network_reconcile_alert
from lattice.backup.lifecycle_events import backup_transition_events
from lattice.core.service_status import (
    WIRE_SERVICE_STATUSES,
    is_service_failed,
)
from lattice.core.worker_auth import (
    WorkerAuthError,
    verify_worker_bearer,
)
from lattice.master.state_machine import (
    heartbeat_worker_target_state,
)
from lattice.core.config import load_config, set_config_value
from lattice.file_access.mount_plan import (
    MountPlanError,
    build_mount_plan,
    write_mount_plan,
)
from lattice.file_access.observations import (
    MountObservationError, normalize_mount_observations,
)
from lattice.backup.observations import (
    BackupObservationError, normalize_backup_observations,
    normalize_backup_target_observations,
)
from lattice.backup.discovery import BackupDiscoveryError, normalize_storage_candidates
from lattice.care.observations import normalize_care_observation
from lattice.backup.identity import (
    BackupIdentityError,
    normalize_backup_identity,
    store_initial_backup_identity_async,
)
from lattice.backup.assignment_state import (
    BackupAssignmentStateError,
    current_assignment_state,
)
from lattice.backup.config_state import (
    BackupConfigStateError,
    current_config_state,
)
from lattice.core.lan_routes import (
    LanRouteError,
    is_local_only_virtual_interface,
    local_lan_routes,
    normalize_reported_routes,
)
from lattice.shell_access.rotation import (
    ShellRotationError,
    finalize_master_rotation,
    process_master_rotation_proposal,
    rotation_promotion_request_for,
)
from lattice.file_access.rotation import (
    FileRotationError,
    finalize_master_rotation as finalize_file_rotation,
    process_master_rotation_proposal as process_file_rotation_proposal,
    rotation_promotion_request_for as file_rotation_promotion_request,
)


router = APIRouter(prefix="/api", tags=["heartbeat"])
logger = logging.getLogger(__name__)


def _seed_current_locators(rows):
    """Seed current authenticated/authoritative peer addresses."""
    locators: dict[str, list[dict]] = {}

    for row in rows:
        if not row[1]:
            continue

        locators.setdefault(
            str(row[0]),
            [],
        ).append(
            {
                "ip": str(row[1]),
                "interface": "",
                "kind": "unknown",
                "priority": 0,
            }
        )

    return locators


async def _begin_heartbeat_transaction(conn, attempts: int = 3) -> None:
    """Acquire the one SQLite writer slot without turning brief contention into a 500.

    Heartbeat clients use a 5 second request timeout. A short per-attempt busy
    timeout plus bounded retry keeps normal contention inside that envelope.
    """
    await conn.execute("PRAGMA busy_timeout=1000")
    for attempt in range(attempts):
        try:
            await conn.execute("BEGIN IMMEDIATE")
            return
        except Exception as exc:
            if not is_sqlite_busy_error(exc):
                raise
            if attempt + 1 >= attempts:
                raise HTTPException(
                    status_code=503,
                    detail="Master state store is busy; retry heartbeat",
                ) from exc
            await asyncio.sleep(0.10 * (2 ** attempt))


@router.post("/heartbeat", dependencies=[])
async def heartbeat(
    request: Request,
    authorization: str = Header(None),
):
    try:
        data = await request.json()

        hostname = data.get("hostname")
        if not hostname:
            raise HTTPException(
                status_code=400,
                detail="Missing hostname",
            )

        try:
            verify_worker_bearer(
                hostname,
                authorization,
            )
        except WorkerAuthError as exc:
            status = (
                401
                if "Authorization" in str(exc)
                else 403
            )
            raise HTTPException(
                status_code=status,
                detail=str(exc),
            ) from exc

        heartbeat_status = data.get("status")
        if (
            heartbeat_status is not None
            and heartbeat_status
            not in {"healthy", "degraded"}
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Heartbeat status must be "
                    "healthy or degraded"
                ),
            )

        reported_fleet_generation = data.get(
            "fleet_generation"
        )

        if (
            reported_fleet_generation is not None
            and (
                isinstance(
                    reported_fleet_generation,
                    bool,
                )
                or not isinstance(
                    reported_fleet_generation,
                    int,
                )
                or reported_fleet_generation < 0
            )
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "fleet_generation must be a "
                    "non-negative integer"
                ),
            )

        try:
            reported_lan_routes = normalize_reported_routes(
                data.get("lan_routes"),
                allow_unknown=False,
            )
        except LanRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        master_local_routes = await __import__("asyncio").to_thread(local_lan_routes)
        mount_observation_payload = data.get("mount_observations")
        if mount_observation_payload is not None and not isinstance(mount_observation_payload, list):
            raise HTTPException(status_code=400, detail="mount_observations must be a list")

        backup_observation_payload = data.get("backup_observations")
        if backup_observation_payload is not None and not isinstance(backup_observation_payload, list):
            raise HTTPException(status_code=400, detail="backup_observations must be a list")

        backup_target_observation_payload = data.get("backup_target_observations")
        if (
            backup_target_observation_payload is not None
            and not isinstance(backup_target_observation_payload, list)
        ):
            raise HTTPException(
                status_code=400, detail="backup_target_observations must be a list"
            )

        backup_storage_candidate_payload = data.get("backup_storage_candidates")
        if (
            backup_storage_candidate_payload is not None
            and not isinstance(backup_storage_candidate_payload, list)
        ):
            raise HTTPException(
                status_code=400, detail="backup_storage_candidates must be a list"
            )

        care_observation_payload = data.get("care_observation")
        if care_observation_payload is not None and not isinstance(care_observation_payload, dict):
            raise HTTPException(status_code=400, detail="care_observation must be an object")

        backup_identity_payload = data.get("backup_identity")
        if backup_identity_payload is not None and not isinstance(backup_identity_payload, dict):
            raise HTTPException(status_code=400, detail="backup_identity must be an object")

        file_rotation_proposal = data.get("file_rotation_proposal")
        if file_rotation_proposal is not None and not isinstance(file_rotation_proposal, dict):
            raise HTTPException(status_code=400, detail="file_rotation_proposal must be an object")
        file_rotation_promoted = data.get("file_rotation_promoted_generation")
        if (file_rotation_promoted is not None and
                (isinstance(file_rotation_promoted, bool) or not isinstance(file_rotation_promoted, int)
                 or file_rotation_promoted < 1)):
            raise HTTPException(status_code=400, detail="file_rotation_promoted_generation must be a positive integer")
        file_transport_generation = data.get("file_transport_generation", 0)
        shell_transport_generation = data.get("shell_transport_generation", 0)
        backup_transport_generation = data.get("backup_transport_generation", 0)
        backup_config_generation = data.get("backup_config_generation", 0)
        for label, value in (
            ("file_transport_generation", file_transport_generation),
            ("shell_transport_generation", shell_transport_generation),
            ("backup_transport_generation", backup_transport_generation),
            ("backup_config_generation", backup_config_generation),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise HTTPException(status_code=400, detail=f"{label} must be a non-negative integer")

        shell_rotation_proposal = data.get("shell_rotation_proposal")
        if shell_rotation_proposal is not None and not isinstance(shell_rotation_proposal, dict):
            raise HTTPException(status_code=400, detail="shell_rotation_proposal must be an object")
        shell_rotation_promoted = data.get("shell_rotation_promoted_generation")
        if (
            shell_rotation_promoted is not None
            and (isinstance(shell_rotation_promoted, bool) or not isinstance(shell_rotation_promoted, int) or shell_rotation_promoted < 1)
        ):
            raise HTTPException(status_code=400, detail="shell_rotation_promoted_generation must be a positive integer")

        services = data.get("services", [])
        if (
            not isinstance(services, list)
            or len(services) > 100
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Services must be a list "
                    "of at most 100 entries"
                ),
            )

        service_failure_reported = False
        network_reconcile_state = None
        allowed_network_states = {
            "healthy", "repaired", "drift_pending", "repair_cooldown",
            "repair_failed", "unsafe_network",
        }

        # Validate everything before taking SQLite's write lock.
        for service in services:
            if not isinstance(service, dict):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Each service report "
                        "must be an object"
                    ),
                )

            name = service.get("name")
            status = service.get("status")

            if (
                not isinstance(name, str)
                or not 1 <= len(name) <= 128
                or not all(
                    ch.isalnum()
                    or ch in "._@-"
                    for ch in name
                )
                or status not in WIRE_SERVICE_STATUSES
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "A service report has "
                        "an invalid name or status"
                    ),
                )

            if name == "network" and "state" in service:
                network_state = service.get("state")
                if network_state not in allowed_network_states:
                    raise HTTPException(status_code=400, detail="Network reconcile state is invalid")
                network_reconcile_state = network_state

            if is_service_failed(status):
                service_failure_reported = True

        reported_at = (
            datetime.now(timezone.utc).isoformat()
        )

        fleet_update = None
        fleet_response_generation = None
        mount_plan = None
        current_manifest = None
        rotation_target_node_id = None
        backup_lifecycle_events: list[dict] = []

        conn = await get_async_db_connection()

        try:
            # Serialize the heartbeat state merge with other writers. Brief
            # local contention is retried and, if still busy, reported as a
            # retryable 503 rather than an internal 500.
            await _begin_heartbeat_transaction(conn)

            cursor = await conn.execute(
                """
                SELECT id, status, failure_count, last_heartbeat_at
                FROM workers
                WHERE hostname = ?
                  AND removed_at IS NULL
                """,
                (hostname,),
            )
            worker_row = await cursor.fetchone()

            if not worker_row:
                await conn.rollback()
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"Unknown worker hostname: "
                        f"{hostname}"
                    ),
                )

            recovery_recheck_worker_id = None
            if worker_row[1] == "down":
                previous_heartbeat = worker_row[3]
                previous_is_stale = previous_heartbeat is None
                if previous_heartbeat is not None:
                    try:
                        previous_at = datetime.fromisoformat(previous_heartbeat)
                        if previous_at.tzinfo is None:
                            previous_at = previous_at.replace(tzinfo=timezone.utc)
                        previous_is_stale = (
                            datetime.now(timezone.utc) - previous_at
                            >= timedelta(seconds=30)
                        )
                    except (TypeError, ValueError):
                        previous_is_stale = True
                if previous_is_stale:
                    recovery_recheck_worker_id = int(worker_row[0])

            await conn.execute(
                """
                UPDATE workers
                SET last_heartbeat_at = ?
                WHERE id = ?
                """,
                (reported_at, worker_row[0]),
            )

            # The authenticated TCP source is only a locator hint.
            # It never changes cryptographic identity or membership.
            source_ip = None

            if request.client is not None:
                try:
                    candidate_source = ipaddress.ip_address(
                        request.client.host
                    )

                    private_lan = any(
                        candidate_source in network
                        for network in (
                            ipaddress.ip_network(
                                "10.0.0.0/8"
                            ),
                            ipaddress.ip_network(
                                "172.16.0.0/12"
                            ),
                            ipaddress.ip_network(
                                "192.168.0.0/16"
                            ),
                        )
                    )

                    if (
                        candidate_source.version == 4
                        and private_lan
                    ):
                        source_ip = str(
                            candidate_source
                        )
                except ValueError:
                    source_ip = None

            if source_ip is not None:
                await conn.execute(
                    """
                    UPDATE workers
                    SET ip = ?
                    WHERE id = ?
                    """,
                    (
                        source_ip,
                        worker_row[0],
                    ),
                )

                await conn.execute(
                    """
                    UPDATE fleet_nodes
                    SET last_known_ip = ?,
                        updated_at = ?
                    WHERE worker_id = ?
                      AND role = 'worker'
                      AND membership_state = 'active'
                    """,
                    (
                        source_ip,
                        reported_at,
                        worker_row[0],
                    ),
                )

            # Fleet synchronization is deliberately piggy-backed on the
            # already authenticated heartbeat. Only an ACTIVE fleet node is
            # eligible. Pending pairing nodes never receive a manifest here.
            if reported_fleet_generation is not None:
                fleet_cursor = await conn.execute(
                    """
                    SELECT
                        node_id,
                        membership_state,
                        membership_generation
                    FROM fleet_nodes
                    WHERE worker_id = ?
                      AND role = 'worker'
                    ORDER BY
                        CASE membership_state
                            WHEN 'active' THEN 0
                            WHEN 'pending' THEN 1
                            ELSE 2
                        END,
                        updated_at DESC
                    LIMIT 1
                    """,
                    (worker_row[0],),
                )
                fleet_node = await fleet_cursor.fetchone()

                if (
                    fleet_node is not None
                    and fleet_node[1] == "active"
                ):
                    rotation_target_node_id = str(fleet_node[0])

                    if backup_identity_payload is not None:
                        try:
                            backup_identity = normalize_backup_identity(
                                backup_identity_payload,
                                expected_node_id=rotation_target_node_id,
                            )
                            await store_initial_backup_identity_async(conn, backup_identity)
                        except BackupIdentityError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=409, detail=str(exc)) from exc

                    # Keep multiple authenticated private-LAN locator hints.
                    # These never establish identity; SSH host-key pinning does.
                    if source_ip is not None:
                        await conn.execute(
                            """INSERT INTO peer_routes
                               (node_id, ip, route_kind, priority, source, last_seen_at)
                               VALUES (?, ?, 'unknown', 25, 'authenticated_source', ?)
                               ON CONFLICT(node_id, ip) DO UPDATE SET
                                 priority=MIN(priority, 25), source='authenticated_source',
                                 last_seen_at=excluded.last_seen_at""",
                            (rotation_target_node_id, source_ip, reported_at),
                        )
                    for route in reported_lan_routes:
                        await conn.execute(
                            """INSERT INTO peer_routes
                               (node_id, ip, interface_name, route_kind, priority, source, last_seen_at)
                               VALUES (?, ?, ?, ?, ?, 'authenticated_report', ?)
                               ON CONFLICT(node_id, ip) DO UPDATE SET
                                 interface_name=excluded.interface_name, route_kind=excluded.route_kind,
                                 priority=excluded.priority, last_seen_at=excluded.last_seen_at""",
                            (rotation_target_node_id, route["ip"], route["interface"],
                             route["kind"], route["priority"], reported_at),
                        )

                    if mount_observation_payload is not None:
                        try:
                            observations = normalize_mount_observations(
                                mount_observation_payload, rotation_target_node_id
                            )
                        except MountObservationError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=400, detail=str(exc)) from exc
                        active_cursor = await conn.execute(
                            "SELECT node_id FROM fleet_nodes WHERE membership_state='active'"
                        )
                        active_ids = {str(row[0]) for row in await active_cursor.fetchall()}
                        for observation in observations:
                            peer_id = observation["peer_node_id"]
                            if peer_id not in active_ids or peer_id == rotation_target_node_id:
                                continue
                            await conn.execute(
                                """INSERT INTO mount_observations
                                   (observer_node_id, peer_node_id, state, last_changed_at,
                                    last_reported_at, error_code)
                                   VALUES (?, ?, ?, ?, ?, ?)
                                   ON CONFLICT(observer_node_id, peer_node_id) DO UPDATE SET
                                     state=excluded.state, last_changed_at=excluded.last_changed_at,
                                     last_reported_at=excluded.last_reported_at,
                                     error_code=excluded.error_code""",
                                (rotation_target_node_id, peer_id, observation["state"],
                                 observation["last_changed_at"], reported_at, observation["error_code"]),
                            )

                    if backup_observation_payload is not None:
                        try:
                            backup_observations = normalize_backup_observations(
                                backup_observation_payload, rotation_target_node_id
                            )
                        except BackupObservationError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=400, detail=str(exc)) from exc
                        for observation in backup_observations:
                            job_cursor = await conn.execute(
                                """SELECT bj.id, bt.target_uuid, bt.friendly_name
                                   FROM backup_jobs bj
                                   JOIN backup_targets bt ON bt.id=bj.target_id
                                   WHERE bj.job_uuid=? AND bj.source_node_id=?
                                   LIMIT 1""",
                                (observation["job_uuid"], rotation_target_node_id),
                            )
                            job_row = await job_cursor.fetchone()
                            # Configuration can legitimately change before a
                            # worker receives it. Ignore stale/unknown jobs rather
                            # than breaking the authenticated heartbeat.
                            if job_row is None or str(job_row[1]) != observation["target_uuid"]:
                                continue
                            previous_cursor = await conn.execute(
                                """SELECT state,last_success_at,last_result,failure_streak
                                   FROM backup_job_observations
                                   WHERE job_id=?""",
                                (job_row[0],),
                            )
                            previous_row = await previous_cursor.fetchone()
                            previous_observation = (
                                {
                                    "state": previous_row[0],
                                    "last_success_at": previous_row[1],
                                    "last_result": previous_row[2],
                                    "failure_streak": previous_row[3],
                                }
                                if previous_row is not None else None
                            )
                            await conn.execute(
                                """INSERT INTO backup_job_observations
                                   (job_id, observer_node_id, state, last_success_at,
                                    last_result, failure_streak, problem_since, maintenance_result,
                                    maintenance_error, credential_missing,
                                    last_deep_verification_at, last_reported_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                   ON CONFLICT(job_id) DO UPDATE SET
                                     observer_node_id=excluded.observer_node_id,
                                     state=excluded.state,
                                     last_success_at=excluded.last_success_at,
                                     last_result=excluded.last_result,
                                     failure_streak=excluded.failure_streak,
                                     problem_since=CASE
                                       WHEN excluded.state IN ('healthy','running','paused') THEN NULL
                                       WHEN backup_job_observations.state IN ('healthy','running','paused')
                                            OR backup_job_observations.problem_since IS NULL
                                         THEN excluded.last_reported_at
                                       ELSE backup_job_observations.problem_since
                                     END,
                                     maintenance_result=excluded.maintenance_result,
                                     maintenance_error=excluded.maintenance_error,
                                     credential_missing=excluded.credential_missing,
                                     last_deep_verification_at=excluded.last_deep_verification_at,
                                     last_reported_at=excluded.last_reported_at""",
                                (
                                    job_row[0], rotation_target_node_id, observation["state"],
                                    observation["last_success_at"], observation["last_result"],
                                    observation["failure_streak"],
                                    None if observation["state"] in {"healthy", "running", "paused"}
                                    else reported_at,
                                    observation["maintenance_result"],
                                    observation["maintenance_error"],
                                    1 if observation["credential_missing"] else 0,
                                    observation["last_deep_verification_at"],
                                    reported_at,
                                ),
                            )
                            backup_lifecycle_events.extend(
                                backup_transition_events(
                                    previous_observation,
                                    observation,
                                    job_id=int(job_row[0]),
                                    source_hostname=hostname,
                                    target_name=str(job_row[2]),
                                )
                            )

                    if backup_target_observation_payload is not None:
                        try:
                            target_observations = normalize_backup_target_observations(
                                backup_target_observation_payload, rotation_target_node_id
                            )
                        except BackupObservationError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=400, detail=str(exc)) from exc
                        for observation in target_observations:
                            target_cursor = await conn.execute(
                                """SELECT id, filesystem_uuid
                                   FROM backup_targets
                                   WHERE target_uuid=? AND host_node_id=?
                                   LIMIT 1""",
                                (observation["target_uuid"], rotation_target_node_id),
                            )
                            target_row = await target_cursor.fetchone()
                            if target_row is None:
                                continue
                            if observation["present"] and str(target_row[1]) != observation["filesystem_uuid"]:
                                # A mounted filesystem claiming the wrong identity
                                # is never accepted as the configured target.
                                continue
                            await conn.execute(
                                """INSERT INTO backup_target_observations
                                   (target_id, observer_node_id, present, problem_since,
                                    filesystem_uuid, mountpoint, total_bytes, free_bytes,
                                    health, last_reported_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                   ON CONFLICT(target_id) DO UPDATE SET
                                     observer_node_id=excluded.observer_node_id,
                                     present=excluded.present,
                                     problem_since=CASE
                                       WHEN excluded.present=1 THEN NULL
                                       WHEN backup_target_observations.present=1
                                            OR backup_target_observations.problem_since IS NULL
                                         THEN excluded.last_reported_at
                                       ELSE backup_target_observations.problem_since
                                     END,
                                     filesystem_uuid=excluded.filesystem_uuid,
                                     mountpoint=excluded.mountpoint,
                                     total_bytes=excluded.total_bytes,
                                     free_bytes=excluded.free_bytes,
                                     health=excluded.health,
                                     last_reported_at=excluded.last_reported_at""",
                                (
                                    target_row[0], rotation_target_node_id,
                                    1 if observation["present"] else 0,
                                    None if observation["present"] else reported_at,
                                    observation["filesystem_uuid"], observation["mountpoint"],
                                    observation["total_bytes"], observation["free_bytes"],
                                    observation["health"], reported_at,
                                ),
                            )

                    if care_observation_payload is not None:
                        try:
                            care_observation = normalize_care_observation(
                                care_observation_payload, rotation_target_node_id
                            )
                        except ValueError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=400, detail=str(exc)) from exc
                        await conn.execute(
                            """INSERT INTO care_observations(
                                   node_id,hostname,status,last_run_at,bytes_reclaimed,
                                   attention_count,critical_count,deferred_reason,findings_json,last_reported_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?)
                               ON CONFLICT(node_id) DO UPDATE SET
                                 hostname=excluded.hostname,status=excluded.status,
                                 last_run_at=excluded.last_run_at,bytes_reclaimed=excluded.bytes_reclaimed,
                                 attention_count=excluded.attention_count,critical_count=excluded.critical_count,
                                 deferred_reason=excluded.deferred_reason,findings_json=excluded.findings_json,
                                 last_reported_at=excluded.last_reported_at""",
                            (
                                rotation_target_node_id, str(care_observation.get("hostname") or hostname)[:255],
                                care_observation["status"], care_observation.get("last_run_at"),
                                care_observation["bytes_reclaimed"], care_observation["attention_count"],
                                care_observation["critical_count"], care_observation.get("deferred_reason"),
                                json.dumps(care_observation.get("findings", []), sort_keys=True, separators=(",", ":")),
                                reported_at,
                            ),
                        )

                    if backup_storage_candidate_payload is not None:
                        try:
                            storage_candidates = normalize_storage_candidates(
                                backup_storage_candidate_payload, rotation_target_node_id
                            )
                        except BackupDiscoveryError as exc:
                            await conn.rollback()
                            raise HTTPException(status_code=400, detail=str(exc)) from exc
                        # This heartbeat is the current mounted storage inventory.
                        # Registered targets are persisted elsewhere; stale
                        # unregistered candidates should disappear promptly.
                        await conn.execute(
                            "DELETE FROM backup_storage_candidates WHERE observer_node_id=?",
                            (rotation_target_node_id,),
                        )
                        for candidate in storage_candidates:
                            await conn.execute(
                                """INSERT INTO backup_storage_candidates(
                                       observer_node_id,filesystem_uuid,name,device,
                                       filesystem_type,mountpoint,size_bytes,removable,last_reported_at)
                                   VALUES(?,?,?,?,?,?,?,?,?)""",
                                (
                                    rotation_target_node_id,
                                    candidate["filesystem_uuid"], candidate["name"],
                                    candidate["device"], candidate["filesystem_type"],
                                    candidate["mountpoint"], candidate["size_bytes"],
                                    1 if candidate["removable"] else 0,
                                    reported_at,
                                ),
                            )

                    state_cursor = await conn.execute(
                        """
                        SELECT
                            generation,
                            manifest,
                            signature
                        FROM fleet_state
                        WHERE id = 1
                        """
                    )
                    fleet_state = await state_cursor.fetchone()

                    if fleet_state is not None:
                        current_generation = int(
                            fleet_state[0]
                        )
                        fleet_response_generation = (
                            current_generation
                        )

                        if (file_transport_generation > current_generation
                                or shell_transport_generation > current_generation):
                            await conn.rollback()
                            raise HTTPException(
                                status_code=409,
                                detail="Worker reports a transport generation newer than the master",
                            )
                        await conn.execute(
                            """UPDATE fleet_nodes SET
                                 file_transport_generation=MAX(file_transport_generation, ?),
                                 shell_transport_generation=MAX(shell_transport_generation, ?),
                                 updated_at=?
                               WHERE node_id=? AND membership_state='active'""",
                            (file_transport_generation, shell_transport_generation,
                             reported_at, rotation_target_node_id),
                        )

                        if (
                            reported_fleet_generation
                            > current_generation
                        ):
                            await conn.rollback()
                            raise HTTPException(
                                status_code=409,
                                detail=(
                                    "Worker reports a fleet "
                                    "generation newer than "
                                    "the master"
                                ),
                            )

                        # Never move this acknowledgement backward if a
                        # worker temporarily loses its local cache.
                        if (
                            reported_fleet_generation
                            > int(fleet_node[2] or 0)
                        ):
                            await conn.execute(
                                """
                                UPDATE fleet_nodes
                                SET membership_generation = ?,
                                    updated_at = ?
                                WHERE node_id = ?
                                """,
                                (
                                    reported_fleet_generation,
                                    reported_at,
                                    fleet_node[0],
                                ),
                            )

                        if (
                            reported_fleet_generation
                            < current_generation
                        ):
                            try:
                                current_manifest = json.loads(
                                    fleet_state[1]
                                )
                            except (
                                TypeError,
                                json.JSONDecodeError,
                            ) as exc:
                                raise RuntimeError(
                                    "Master fleet manifest "
                                    "cannot be decoded"
                                ) from exc

                            if not isinstance(
                                current_manifest,
                                dict,
                            ):
                                raise RuntimeError(
                                    "Master fleet manifest "
                                    "has an invalid format"
                                )

                            fleet_update = {
                                "manifest":
                                    current_manifest,
                                "signature":
                                    fleet_state[2],
                            }

                        # Build a locator plan for the CURRENT signed
                        # generation. Hostname/user come only from the
                        # manifest; SQLite supplies only last-known IPs.
                        if current_manifest is None:
                            try:
                                current_manifest = json.loads(
                                    fleet_state[1]
                                )
                            except (
                                TypeError,
                                json.JSONDecodeError,
                            ):
                                current_manifest = None

                        if isinstance(
                            current_manifest,
                            dict,
                        ):
                            locator_cursor = await conn.execute(
                                """
                                SELECT
                                    fn.node_id,
                                    COALESCE(
                                        w.ip,
                                        fn.last_known_ip
                                    )
                                FROM fleet_nodes AS fn
                                LEFT JOIN workers AS w
                                  ON w.id = fn.worker_id
                                WHERE fn.membership_state = 'active'
                                """
                            )

                            locator_rows = await locator_cursor.fetchall()

                            # The current workers.ip / last_known_ip is the
                            # authoritative live locator. Historical routes
                            # remain available as fallbacks but cannot outrank it.
                            locators = _seed_current_locators(
                                locator_rows
                            )

                            route_cursor = await conn.execute(
                                """SELECT node_id, ip, interface_name, route_kind, priority
                                   FROM peer_routes
                                   WHERE last_seen_at >= datetime('now', '-30 days')
                                   ORDER BY node_id, priority ASC,
                                            CASE WHEN last_success_at IS NULL THEN 1 ELSE 0 END,
                                            last_success_at DESC"""
                            )
                            for route in await route_cursor.fetchall():
                                interface = str(route[2] or "")
                                route_kind = str(route[3] or "unknown")
                                if (
                                    route_kind == "unknown"
                                    or is_local_only_virtual_interface(interface)
                                ):
                                    continue
                                bucket = locators.setdefault(str(route[0]), [])
                                if any(item["ip"] == route[1] for item in bucket):
                                    continue
                                bucket.append({
                                    "ip": str(route[1]),
                                    "interface": interface,
                                    "kind": route_kind,
                                    "priority": int(route[4] or 50),
                                })

                            master_member = next(
                                (member for member in current_manifest.get("members", [])
                                 if member.get("role") == "master"),
                                None,
                            )
                            if master_member is not None:
                                master_bucket = locators.setdefault(master_member["node_id"], [])
                                for route in master_local_routes:
                                    if not any(item["ip"] == route["ip"] for item in master_bucket):
                                        master_bucket.append(dict(route))

                            try:
                                mount_plan = build_mount_plan(
                                    current_manifest,
                                    locators,
                                    port=(
                                        load_config()
                                        .file_access
                                        .port
                                    ),
                                )
                            except MountPlanError as exc:
                                logger.warning(
                                    "Could not construct fleet "
                                    "mount plan: %s",
                                    exc,
                                )
                                mount_plan = None

            # One UPSERT per service instead of SELECT + UPDATE/INSERT.
            for service in services:
                await conn.execute(
                    """
                    INSERT INTO services (
                        name,
                        worker_id,
                        type,
                        status,
                        last_reported_at
                    )
                    VALUES (?, ?, 'systemd', ?, ?)
                    ON CONFLICT(worker_id, name)
                    DO UPDATE SET
                        status = excluded.status,
                        type = excluded.type,
                        last_reported_at =
                            excluded.last_reported_at
                    """,
                    (
                        service["name"],
                        worker_row[0],
                        service["status"],
                        reported_at,
                    ),
                )

            effective_status = heartbeat_status

            if service_failure_reported:
                effective_status = "degraded"

            if effective_status in {
                "healthy",
                "degraded",
            }:
                target_state = (
                    heartbeat_worker_target_state(
                        worker_row[1],
                        worker_row[2],
                        effective_status,
                    )
                )

                if (
                    target_state.value
                    != worker_row[1]
                ):
                    await conn.execute(
                        """
                        UPDATE workers
                        SET status = ?
                        WHERE id = ?
                        """,
                        (
                            target_state.value,
                            worker_row[0],
                        ),
                    )

            await conn.commit()

        except HTTPException:
            try:
                await conn.rollback()
            except Exception:
                pass
            raise

        except Exception:
            try:
                await conn.rollback()
            except Exception:
                pass
            raise

        finally:
            await conn.close()

        if recovery_recheck_worker_id is not None:
            try:
                await asyncio.to_thread(
                    set_config_value,
                    f"health.recheck.{recovery_recheck_worker_id}",
                    "true",
                )
                logger.info(
                    "Authenticated recovery heartbeat from %s requested an immediate health recheck",
                    hostname,
                )
            except Exception as exc:
                logger.error(
                    "Could not request immediate recovery health recheck for %s: %s",
                    hostname,
                    exc,
                )

        if backup_lifecycle_events:
            backup_event_worker_id = int(worker_row[0]) if worker_row is not None else None

            async def _log_backup_lifecycle_events_in_background():
                for event in backup_lifecycle_events:
                    try:
                        await asyncio.to_thread(
                            log_event,
                            backup_event_worker_id,
                            event["type"],
                            event["severity"],
                            event["message"],
                            event.get("details"),
                        )
                    except Exception as exc:
                        logger.error(
                            "Could not log backup lifecycle event for %s: %s",
                            hostname,
                            exc,
                        )

            asyncio.create_task(_log_backup_lifecycle_events_in_background())

        if network_reconcile_state is not None and worker_row is not None:

            async def _sync_network_alert_in_background():
                try:
                    await asyncio.to_thread(
                        sync_network_reconcile_alert,
                        int(worker_row[0]),
                        hostname,
                        network_reconcile_state,
                    )
                except Exception as exc:
                    logger.error(
                        "Could not synchronize network alert for %s: %s",
                        hostname,
                        exc,
                    )

            asyncio.create_task(_sync_network_alert_in_background())

        # The master uses the same trust-bound locator plan locally.
        # Failure to write it must not invalidate an otherwise healthy
        # authenticated heartbeat.
        if (
            mount_plan is not None
            and isinstance(
                current_manifest,
                dict,
            )
        ):
            try:
                await __import__(
                    "asyncio"
                ).to_thread(
                    write_mount_plan,
                    current_manifest,
                    mount_plan,
                )
            except (
                MountPlanError,
                OSError,
            ) as exc:
                logger.error(
                    "Could not update local master "
                    "mount plan: %s",
                    exc,
                )

        # Shell key rollover is driven only by authenticated active peers and
        # committed outside the heartbeat transaction. A new generation is
        # returned naturally on the next heartbeat.
        if rotation_target_node_id is not None:
            try:
                if shell_rotation_proposal is not None:
                    await __import__("asyncio").to_thread(
                        process_master_rotation_proposal,
                        rotation_target_node_id,
                        shell_rotation_proposal,
                    )
                if shell_rotation_promoted is not None:
                    await __import__("asyncio").to_thread(
                        finalize_master_rotation,
                        rotation_target_node_id,
                        shell_rotation_promoted,
                    )
            except ShellRotationError as exc:
                logger.error("Shell key rotation update from %s was rejected: %s", hostname, exc)

        # File-channel rollover uses the same authenticated heartbeat but a
        # separate keypair and serialized fleet generation sequence.
        if rotation_target_node_id is not None:
            try:
                if file_rotation_proposal is not None:
                    await __import__("asyncio").to_thread(
                        process_file_rotation_proposal,
                        rotation_target_node_id,
                        file_rotation_proposal,
                    )
                if file_rotation_promoted is not None:
                    await __import__("asyncio").to_thread(
                        finalize_file_rotation,
                        rotation_target_node_id,
                        file_rotation_promoted,
                    )
            except FileRotationError as exc:
                logger.error("File key rotation update from %s was rejected: %s", hostname, exc)

        file_rotation_request = None
        if rotation_target_node_id is not None:
            try:
                file_rotation_request = await __import__("asyncio").to_thread(
                    file_rotation_promotion_request, rotation_target_node_id
                )
            except FileRotationError as exc:
                logger.error("Could not evaluate file promotion for %s: %s", hostname, exc)

        shell_rotation_request = None
        if rotation_target_node_id is not None:
            try:
                shell_rotation_request = await __import__("asyncio").to_thread(
                    rotation_promotion_request_for, rotation_target_node_id
                )
            except ShellRotationError as exc:
                logger.error("Could not evaluate shell promotion for %s: %s", hostname, exc)

        backup_config_update = None
        if rotation_target_node_id is not None:
            try:
                signed_config_state = await __import__("asyncio").to_thread(
                    current_config_state
                )
                if (
                    signed_config_state is not None
                    and int(signed_config_state["config"]["generation"])
                    > backup_config_generation
                ):
                    backup_config_update = signed_config_state
            except BackupConfigStateError as exc:
                logger.error("Could not read signed backup configuration state: %s", exc)

        backup_assignment_update = None
        if rotation_target_node_id is not None:
            try:
                signed_backup_state = await __import__("asyncio").to_thread(
                    current_assignment_state
                )
                if (
                    signed_backup_state is not None
                    and int(signed_backup_state["assignment"]["generation"])
                    > backup_transport_generation
                ):
                    backup_assignment_update = signed_backup_state
            except BackupAssignmentStateError as exc:
                logger.error("Could not read signed backup assignment state: %s", exc)

        response_payload = {
            "status": "ok",
        }

        if fleet_response_generation is not None:
            response_payload[
                "fleet_generation"
            ] = fleet_response_generation

        if fleet_update is not None:
            response_payload[
                "fleet_update"
            ] = fleet_update

        if mount_plan is not None:
            response_payload[
                "mount_plan"
            ] = mount_plan

        if backup_config_update is not None:
            response_payload["backup_config"] = backup_config_update

        if backup_assignment_update is not None:
            response_payload["backup_assignment"] = backup_assignment_update

        if file_rotation_request is not None:
            response_payload["file_rotation"] = file_rotation_request

        if shell_rotation_request is not None:
            response_payload["shell_rotation"] = shell_rotation_request

        return response_payload

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(
            "Heartbeat processing failed: %s",
            exc,
        )
        raise HTTPException(
            status_code=500,
            detail="Heartbeat processing failed",
        ) from exc
