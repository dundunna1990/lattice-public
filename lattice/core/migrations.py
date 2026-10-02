import sqlite3
import logging

logger = logging.getLogger(__name__)

def run_migrations(conn: sqlite3.Connection) -> None:
    # Database-wide journal configuration belongs to initialization/migration,
    # not every connection. WAL allows readers and a writer to coexist.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # Create tables with all required columns
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY,
            hostname TEXT NOT NULL UNIQUE,
            status TEXT DEFAULT 'unknown',
            ssh_host_key_fingerprint TEXT,
            last_heartbeat_at TEXT,
            failure_count INTEGER DEFAULT 0,
            removed_at TEXT,
            ip TEXT,
            ssh_user TEXT,
            last_instance_id TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            worker_id INTEGER,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            worker_id INTEGER,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            trigger_event_id INTEGER,
            fired_at TEXT NOT NULL,
            acked_at TEXT,
            resolved_at TEXT,
            resolution_event_id INTEGER,
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        );

        CREATE TABLE IF NOT EXISTS circuit_breaker_state (
            id INTEGER PRIMARY KEY,
            worker_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            failure_count INTEGER DEFAULT 0,
            opened_at TEXT,
            half_open_at TEXT,
            half_open_token TEXT,
            probe_started_at TEXT,
            UNIQUE(worker_id, action)
        );

        CREATE TABLE IF NOT EXISTS healing_attempts (
            id INTEGER PRIMARY KEY,
            worker_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            action TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            result TEXT,
            error_message TEXT,
            UNIQUE(worker_id, service, started_at)
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            worker_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            last_reported_at TEXT,
            UNIQUE(worker_id, name),
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        );

        CREATE TABLE IF NOT EXISTS fleet_nodes (
            node_id TEXT PRIMARY KEY,
            worker_id INTEGER,
            hostname TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('master', 'worker')),
            main_user TEXT NOT NULL,
            main_uid INTEGER NOT NULL,
            main_gid INTEGER NOT NULL,
            file_public_key TEXT,
            file_key_generation INTEGER NOT NULL DEFAULT 0,
            file_host_public_key TEXT,
            file_host_key_fingerprint TEXT,
            shell_public_key TEXT,
            shell_key_generation INTEGER NOT NULL DEFAULT 0,
            shell_host_public_key TEXT,
            shell_host_key_fingerprint TEXT,
            backup_public_key TEXT,
            backup_key_generation INTEGER NOT NULL DEFAULT 0,
            backup_host_public_key TEXT,
            backup_host_key_fingerprint TEXT,
            file_transport_generation INTEGER NOT NULL DEFAULT 0,
            shell_transport_generation INTEGER NOT NULL DEFAULT 0,
            last_known_ip TEXT,
            membership_state TEXT NOT NULL DEFAULT 'pending'
                CHECK(membership_state IN ('pending', 'active', 'revoked')),
            membership_generation INTEGER NOT NULL DEFAULT 0,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        );

        CREATE TABLE IF NOT EXISTS fleet_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            fleet_id TEXT NOT NULL UNIQUE,
            generation INTEGER NOT NULL DEFAULT 0,
            manifest TEXT NOT NULL,
            signature TEXT NOT NULL,
            signing_public_key TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fleet_pending_updates (
            target_node_id TEXT PRIMARY KEY,
            generation INTEGER NOT NULL UNIQUE,
            manifest TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS shares (
            share_id TEXT PRIMARY KEY,
            owner_node_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('home', 'drive', 'home_external')),
            display_name TEXT NOT NULL,
            source_path TEXT NOT NULL,
            filesystem_uuid TEXT,
            partition_uuid TEXT,
            device_serial TEXT,
            approved INTEGER NOT NULL DEFAULT 0 CHECK(approved IN (0, 1)),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            permission_policy TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS mount_preferences (
            peer_node_id TEXT PRIMARY KEY,
            desired_state TEXT NOT NULL DEFAULT 'mounted'
                CHECK(desired_state IN ('mounted', 'paused')),
            paused_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mount_state (
            peer_node_id TEXT PRIMARY KEY,
            state TEXT NOT NULL DEFAULT 'unknown'
                CHECK(state IN (
                    'unknown',
                    'discovering',
                    'connecting',
                    'mounted',
                    'offline',
                    'stale',
                    'mount_problem',
                    'reconnecting',
                    'paused'
                )),
            mount_path TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            last_probe_at TEXT,
            last_success_at TEXT,
            next_retry_at TEXT,
            error_code TEXT,
            error_message TEXT,
            problem_since TEXT,
            alert_id INTEGER,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mount_observations (
            observer_node_id TEXT NOT NULL,
            peer_node_id TEXT NOT NULL,
            state TEXT NOT NULL,
            last_changed_at TEXT,
            last_reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            error_code TEXT,
            PRIMARY KEY (observer_node_id, peer_node_id),
            FOREIGN KEY (observer_node_id) REFERENCES fleet_nodes(node_id),
            FOREIGN KEY (peer_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS fleet_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS shell_key_rotations (
            target_node_id TEXT PRIMARY KEY,
            next_generation INTEGER NOT NULL,
            next_public_key TEXT NOT NULL,
            next_host_public_key TEXT NOT NULL,
            next_host_key_fingerprint TEXT NOT NULL,
            overlap_generation INTEGER,
            stage TEXT NOT NULL DEFAULT 'proposed'
                CHECK(stage IN ('proposed', 'overlap', 'promote_requested')),
            alert_id INTEGER,
            proposed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS file_key_rotations (
            target_node_id TEXT PRIMARY KEY,
            next_generation INTEGER NOT NULL,
            next_public_key TEXT NOT NULL,
            next_host_public_key TEXT NOT NULL,
            next_host_key_fingerprint TEXT NOT NULL,
            overlap_generation INTEGER,
            stage TEXT NOT NULL DEFAULT 'proposed'
                CHECK(stage IN ('proposed', 'overlap', 'promote_requested')),
            alert_id INTEGER,
            proposed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS peer_routes (
            node_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            interface_name TEXT,
            route_kind TEXT NOT NULL DEFAULT 'unknown'
                CHECK(route_kind IN ('ethernet', 'wifi', 'unknown')),
            priority INTEGER NOT NULL DEFAULT 50,
            source TEXT NOT NULL DEFAULT 'authenticated_report'
                CHECK(source IN ('authenticated_source', 'authenticated_report', 'local', 'dns')),
            last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_success_at TEXT,
            last_failure_at TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (node_id, ip)
        );

        CREATE TABLE IF NOT EXISTS shell_connection_state (
            peer_node_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'unknown'
                CHECK(state IN ('unknown', 'connected', 'unavailable', 'retired')),
            selected_ip TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            problem_since TEXT,
            last_attempt_at TEXT,
            last_connected_at TEXT,
            last_disconnected_at TEXT,
            alert_id INTEGER,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS shell_connection_history (
            id INTEGER PRIMARY KEY,
            peer_node_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            event_type TEXT NOT NULL
                CHECK(event_type IN ('connected', 'recovered', 'unavailable', 'route_switch', 'retired')),
            ip TEXT,
            occurred_at TEXT NOT NULL,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_config_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            generation INTEGER NOT NULL,
            config TEXT NOT NULL,
            signature TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_runtime_policy (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            generation INTEGER NOT NULL,
            schedule_hour INTEGER NOT NULL,
            retention_daily INTEGER NOT NULL,
            retention_weekly INTEGER NOT NULL,
            retention_monthly INTEGER NOT NULL,
            free_space_reserve_percent INTEGER NOT NULL,
            deep_verification_days INTEGER NOT NULL,
            persistent_alert_seconds INTEGER NOT NULL,
            bandwidth_limit_kib INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_config_applied_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            generation INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_assignment_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            generation INTEGER NOT NULL,
            assignment TEXT NOT NULL,
            signature TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_storage_candidates (
            observer_node_id TEXT NOT NULL,
            filesystem_uuid TEXT NOT NULL,
            name TEXT NOT NULL,
            device TEXT NOT NULL,
            filesystem_type TEXT NOT NULL,
            mountpoint TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            removable INTEGER NOT NULL CHECK(removable IN (0, 1)),
            last_reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (observer_node_id, filesystem_uuid),
            FOREIGN KEY (observer_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS backup_targets (
            id INTEGER PRIMARY KEY,
            target_uuid TEXT NOT NULL UNIQUE,
            friendly_name TEXT NOT NULL,
            host_node_id TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK(target_type IN ('local_storage', 'remote_storage')),
            filesystem_uuid TEXT NOT NULL,
            repository_root TEXT NOT NULL,
            repository_relative_path TEXT NOT NULL DEFAULT 'LatticeBackups',
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS backup_jobs (
            id INTEGER PRIMARY KEY,
            job_uuid TEXT NOT NULL UNIQUE,
            source_node_id TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            source_path TEXT NOT NULL,
            schedule TEXT NOT NULL DEFAULT 'nightly',
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0, 1)),
            pause_reason TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_node_id, target_id),
            FOREIGN KEY (source_node_id) REFERENCES fleet_nodes(node_id),
            FOREIGN KEY (target_id) REFERENCES backup_targets(id)
        );

        CREATE TABLE IF NOT EXISTS backup_runs (
            id INTEGER PRIMARY KEY,
            job_id INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            result TEXT NOT NULL CHECK(result IN ('running','successful','interrupted','failed','cancelled')),
            snapshot_id TEXT,
            bytes_added INTEGER,
            error_code TEXT,
            error_message TEXT,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS backup_maintenance_state (
            job_id INTEGER PRIMARY KEY,
            last_retention_at TEXT,
            last_deep_verification_at TEXT,
            last_result TEXT CHECK(last_result IN ('healthy','degraded','failed')),
            last_error TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS backup_restore_sessions (
            id INTEGER PRIMARY KEY,
            session_uuid TEXT NOT NULL UNIQUE,
            job_id INTEGER NOT NULL,
            snapshot_id TEXT NOT NULL,
            selection_path TEXT NOT NULL,
            staging_path TEXT NOT NULL,
            original_destination TEXT NOT NULL,
            placed_destination TEXT,
            state TEXT NOT NULL CHECK(state IN ('staged','placed','cancelled','failed')),
            conflict INTEGER NOT NULL DEFAULT 0 CHECK(conflict IN (0,1)),
            error_message TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS backup_verifications (
            id INTEGER PRIMARY KEY,
            job_id INTEGER NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('quick','deep')),
            started_at TEXT NOT NULL,
            finished_at TEXT,
            result TEXT NOT NULL CHECK(result IN ('running','successful','failed')),
            error_message TEXT,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS backup_preflight_state (
            job_id INTEGER PRIMARY KEY,
            included_bytes INTEGER NOT NULL,
            logical_bytes INTEGER NOT NULL,
            mount_targets_json TEXT NOT NULL DEFAULT '[]',
            directory_sizes_json TEXT NOT NULL DEFAULT '{}',
            last_warning TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS backup_job_observations (
            job_id INTEGER PRIMARY KEY,
            observer_node_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('healthy','running','pending','paused','never_backed_up')),
            last_success_at TEXT,
            last_result TEXT,
            failure_streak INTEGER NOT NULL DEFAULT 0,
            problem_since TEXT,
            maintenance_result TEXT,
            maintenance_error TEXT,
            credential_missing INTEGER NOT NULL DEFAULT 0 CHECK(credential_missing IN (0,1)),
            last_deep_verification_at TEXT,
            last_reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES backup_jobs(id),
            FOREIGN KEY (observer_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS backup_target_observations (
            target_id INTEGER PRIMARY KEY,
            observer_node_id TEXT NOT NULL,
            present INTEGER NOT NULL CHECK(present IN (0, 1)),
            problem_since TEXT,
            filesystem_uuid TEXT,
            mountpoint TEXT,
            total_bytes INTEGER,
            free_bytes INTEGER,
            health TEXT NOT NULL DEFAULT 'unknown',
            last_reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES backup_targets(id),
            FOREIGN KEY (observer_node_id) REFERENCES fleet_nodes(node_id)
        );

        CREATE TABLE IF NOT EXISTS care_runs (
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            trigger TEXT NOT NULL CHECK(trigger IN ('scheduled','manual')),
            status TEXT NOT NULL CHECK(status IN ('healthy','attention','critical','stale','off')),
            bytes_reclaimed INTEGER NOT NULL DEFAULT 0,
            attention_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            deferred_reason TEXT,
            plan_json TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS care_actions (
            id INTEGER PRIMARY KEY,
            run_id INTEGER NOT NULL,
            operation TEXT NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('successful','failed','skipped','deferred')),
            bytes_reclaimed INTEGER NOT NULL DEFAULT 0,
            detail TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (run_id) REFERENCES care_runs(id)
        );

        CREATE TABLE IF NOT EXISTS care_findings (
            id INTEGER PRIMARY KEY,
            run_id INTEGER NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('attention','critical')),
            code TEXT NOT NULL,
            subject TEXT NOT NULL,
            detail TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            cleared_at TEXT,
            FOREIGN KEY (run_id) REFERENCES care_runs(id)
        );

        CREATE TABLE IF NOT EXISTS care_observations (
            node_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('healthy','attention','critical','stale','off')),
            last_run_at TEXT,
            bytes_reclaimed INTEGER NOT NULL DEFAULT 0,
            attention_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            deferred_reason TEXT,
            findings_json TEXT NOT NULL DEFAULT '[]',
            last_reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (node_id) REFERENCES fleet_nodes(node_id)
        );
    """)

    cursor = conn.cursor()

    # Add missing columns to circuit_breaker_state (idempotent)
    cursor.execute("PRAGMA table_info(circuit_breaker_state)")
    cb_cols = [col[1] for col in cursor.fetchall()]
    if 'half_open_token' not in cb_cols:
        cursor.execute("ALTER TABLE circuit_breaker_state ADD COLUMN half_open_token TEXT")
    if 'probe_started_at' not in cb_cols:
        cursor.execute("ALTER TABLE circuit_breaker_state ADD COLUMN probe_started_at TEXT")

    # Add missing columns to workers (if not already present)
    cursor.execute("PRAGMA table_info(workers)")
    worker_cols = [col[1] for col in cursor.fetchall()]
    if 'ip' not in worker_cols:
        cursor.execute("ALTER TABLE workers ADD COLUMN ip TEXT")
    if 'ssh_user' not in worker_cols:
        cursor.execute("ALTER TABLE workers ADD COLUMN ssh_user TEXT")
    if 'last_instance_id' not in worker_cols:
        cursor.execute("ALTER TABLE workers ADD COLUMN last_instance_id TEXT")

    # Add dedicated shell-channel identity columns for older databases.
    cursor.execute("PRAGMA table_info(fleet_nodes)")
    fleet_cols = [col[1] for col in cursor.fetchall()]
    for column, definition in (
        ("shell_public_key", "TEXT"),
        ("shell_key_generation", "INTEGER NOT NULL DEFAULT 0"),
        ("shell_host_public_key", "TEXT"),
        ("shell_host_key_fingerprint", "TEXT"),
        ("backup_public_key", "TEXT"),
        ("backup_key_generation", "INTEGER NOT NULL DEFAULT 0"),
        ("backup_host_public_key", "TEXT"),
        ("backup_host_key_fingerprint", "TEXT"),
        ("file_transport_generation", "INTEGER NOT NULL DEFAULT 0"),
        ("shell_transport_generation", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if column not in fleet_cols:
            cursor.execute(f"ALTER TABLE fleet_nodes ADD COLUMN {column} {definition}")

    cursor.execute("PRAGMA table_info(backup_runtime_policy)")
    backup_policy_cols = [col[1] for col in cursor.fetchall()]
    if "bandwidth_limit_kib" not in backup_policy_cols:
        cursor.execute(
            "ALTER TABLE backup_runtime_policy ADD COLUMN bandwidth_limit_kib INTEGER NOT NULL DEFAULT 0"
        )

    cursor.execute("PRAGMA table_info(backup_jobs)")
    backup_job_cols = [col[1] for col in cursor.fetchall()]
    if "enabled" not in backup_job_cols:
        cursor.execute(
            "ALTER TABLE backup_jobs ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 "
            "CHECK(enabled IN (0, 1))"
        )

    cursor.execute("PRAGMA table_info(backup_targets)")
    backup_target_cols = [col[1] for col in cursor.fetchall()]
    if "repository_relative_path" not in backup_target_cols:
        cursor.execute(
            "ALTER TABLE backup_targets ADD COLUMN repository_relative_path "
            "TEXT NOT NULL DEFAULT 'LatticeBackups'"
        )

    # Keep development/interrupted Phase Two databases forward-compatible if
    # the shell rotation table predates persistent alert tracking.
    cursor.execute("PRAGMA table_info(shell_key_rotations)")
    shell_rotation_cols = [col[1] for col in cursor.fetchall()]
    if "alert_id" not in shell_rotation_cols:
        cursor.execute(
            "ALTER TABLE shell_key_rotations ADD COLUMN alert_id INTEGER"
        )

    cursor.execute("PRAGMA table_info(backup_job_observations)")
    backup_job_obs_cols = [col[1] for col in cursor.fetchall()]
    for column, definition in (
        ("problem_since", "TEXT"),
        ("failure_streak", "INTEGER NOT NULL DEFAULT 0"),
        ("maintenance_result", "TEXT"),
        ("maintenance_error", "TEXT"),
        ("credential_missing", "INTEGER NOT NULL DEFAULT 0"),
        ("last_deep_verification_at", "TEXT"),
    ):
        if column not in backup_job_obs_cols:
            cursor.execute(f"ALTER TABLE backup_job_observations ADD COLUMN {column} {definition}")

    cursor.execute("PRAGMA table_info(care_runs)")
    care_run_cols = [col[1] for col in cursor.fetchall()]
    if "plan_json" not in care_run_cols:
        cursor.execute("ALTER TABLE care_runs ADD COLUMN plan_json TEXT NOT NULL DEFAULT '[]'")

    cursor.execute("PRAGMA table_info(backup_target_observations)")
    backup_target_obs_cols = [col[1] for col in cursor.fetchall()]
    if "problem_since" not in backup_target_obs_cols:
        cursor.execute("ALTER TABLE backup_target_observations ADD COLUMN problem_since TEXT")

    # Add mount-manager alert tracking columns for databases
    # created before the persistent file-access alert layer.
    cursor.execute("PRAGMA table_info(mount_state)")
    mount_state_cols = [
        col[1]
        for col in cursor.fetchall()
    ]

    if "problem_since" not in mount_state_cols:
        cursor.execute(
            "ALTER TABLE mount_state "
            "ADD COLUMN problem_since TEXT"
        )

    if "alert_id" not in mount_state_cols:
        cursor.execute(
            "ALTER TABLE mount_state "
            "ADD COLUMN alert_id INTEGER"
        )

    # Add missing columns to services (if not already present)
    cursor.execute("PRAGMA table_info(services)")
    service_cols = [col[1] for col in cursor.fetchall()]
    if 'type' not in service_cols:
        cursor.execute("ALTER TABLE services ADD COLUMN type TEXT NOT NULL DEFAULT 'unknown'")
    if 'status' not in service_cols:
        cursor.execute("ALTER TABLE services ADD COLUMN status TEXT DEFAULT 'unknown'")
    if 'last_reported_at' not in service_cols:
        cursor.execute("ALTER TABLE services ADD COLUMN last_reported_at TEXT")
    cursor.execute(
        "DELETE FROM services WHERE id NOT IN "
        "(SELECT MAX(id) FROM services GROUP BY worker_id, name)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_services_worker_name "
        "ON services(worker_id, name)"
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_fleet_nodes_membership "
        "ON fleet_nodes(membership_state, hostname)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_fleet_nodes_worker_id "
        "ON fleet_nodes(worker_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_shares_owner "
        "ON shares(owner_node_id, enabled)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_mount_state_status "
        "ON mount_state(state, next_retry_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_mount_observations_peer "
        "ON mount_observations(peer_node_id, state)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_peer_routes_node "
        "ON peer_routes(node_id, priority, last_success_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_shell_history_peer_time "
        "ON shell_connection_history(peer_node_id, occurred_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_jobs_source "
        "ON backup_jobs(source_node_id, paused)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_runs_job_time "
        "ON backup_runs(job_id, started_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_targets_host "
        "ON backup_targets(host_node_id, enabled)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_storage_candidates_seen "
        "ON backup_storage_candidates(last_reported_at, observer_node_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_verifications_job_time "
        "ON backup_verifications(job_id, started_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_backup_restore_sessions_job_time "
        "ON backup_restore_sessions(job_id, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_care_runs_started "
        "ON care_runs(started_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_care_findings_open "
        "ON care_findings(cleared_at, severity)"
    )

    # Insert test worker and service
    # Test data removed (was: INSERT INTO workers test-worker)
    # Test data removed (was: INSERT INTO services test-service)
    conn.commit()
