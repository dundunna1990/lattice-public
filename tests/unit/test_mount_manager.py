from datetime import (
    datetime,
    timezone,
)
import os
from pathlib import Path
import sqlite3
import subprocess
import uuid

from lattice.core.migrations import (
    run_migrations,
)
from lattice.file_access.mount_manager import (
    FUSERMOUNT_BINARY,
    SSHFS_BINARY,
    STAT_BINARY,
    MountEntry,
    MountManager,
    PeerMountPlan,
    bounded_retry_seconds,
    build_sshfs_command,
    find_mount_entry,
    is_lattice_sshfs_mount,
    mount_path_for,
)


NODE_ID = (
    "11111111-1111-4111-8111-111111111111"
)


def _plan():
    return PeerMountPlan(
        node_id=NODE_ID,
        hostname="worker-node",
        ip="10.77.0.201",
        remote_user="workeruser",
        local_uid=os.getuid() or 1000,
        local_gid=os.getgid(),
        port=22022,
    )


def _db(tmp_path):
    conn = sqlite3.connect(
        tmp_path / "mount.db"
    )
    conn.row_factory = sqlite3.Row
    conn.execute(
        "PRAGMA foreign_keys=ON"
    )
    run_migrations(conn)
    return conn


def _mountinfo(path, fstype="fuse.sshfs"):
    return (
        "36 25 0:45 / "
        f"{path} "
        "rw,nosuid,nodev - "
        f"{fstype} "
        "workeruser@10.77.0.201:/Home "
        "rw,user_id=0\n"
    )


def test_mount_path_uses_permanent_node_id(
    tmp_path,
):
    path = mount_path_for(
        NODE_ID,
        root=tmp_path,
    )

    assert path == (
        tmp_path / NODE_ID
    )

    assert "worker-node" not in str(path)


def test_sshfs_command_is_strict_and_noninteractive(
    tmp_path,
):
    plan = _plan()

    command = build_sshfs_command(
        plan,
        mount_root=tmp_path,
        client_key=Path(
            "/etc/lattice/file-ssh/client_ed25519"
        ),
        known_hosts=Path(
            "/etc/lattice/file-ssh/known_hosts"
        ),
    )

    joined = " ".join(command)

    assert command[0] == SSHFS_BINARY
    assert (
        "workeruser@10.77.0.201:/Home"
        in command
    )
    assert str(
        tmp_path / NODE_ID
    ) in command

    assert "StrictHostKeyChecking=yes" in joined
    assert "StrictHostKeyChecking=no" not in joined
    assert "BatchMode=yes" in joined
    assert "NumberOfPasswordPrompts=0" in joined
    assert (
        f"HostKeyAlias=lattice-node-{NODE_ID}"
        in joined
    )
    assert "allow_other" in command
    assert "default_permissions" in command
    assert "cache=no" in command
    assert "reconnect" in command


def test_retry_backoff_is_bounded():
    assert bounded_retry_seconds(
        1,
        initial=2,
        maximum=300,
    ) == 2

    assert bounded_retry_seconds(
        2,
        initial=2,
        maximum=300,
    ) == 4

    assert bounded_retry_seconds(
        10,
        initial=2,
        maximum=300,
    ) == 300


def test_mountinfo_requires_exact_target(
    tmp_path,
):
    target = tmp_path / NODE_ID

    entry = find_mount_entry(
        target,
        _mountinfo(target),
    )

    assert entry is not None
    assert (
        entry.filesystem_type
        == "fuse.sshfs"
    )

    other = find_mount_entry(
        tmp_path / str(uuid.uuid4()),
        _mountinfo(target),
    )

    assert other is None


def test_only_lattice_sshfs_mount_is_owned(
    tmp_path,
):
    target = tmp_path / NODE_ID

    good = MountEntry(
        mount_point=str(
            target.absolute()
        ),
        filesystem_type="fuse.sshfs",
        source=(
            "workeruser@10.77.0.201:/Home"
        ),
    )

    bad = MountEntry(
        mount_point=str(
            target.absolute()
        ),
        filesystem_type="ext4",
        source="/dev/sda1",
    )

    assert is_lattice_sshfs_mount(
        target,
        good,
        mount_root=tmp_path,
    )

    assert not is_lattice_sshfs_mount(
        target,
        bad,
        mount_root=tmp_path,
    )


def test_paused_peer_never_mounts(
    tmp_path,
):
    conn = _db(tmp_path)
    plan = _plan()

    conn.execute(
        """
        INSERT INTO mount_preferences (
            peer_node_id,
            desired_state
        )
        VALUES (?, 'paused')
        """,
        (NODE_ID,),
    )
    conn.commit()

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: "",
        mount_root=tmp_path / "mnt",
        clock=lambda: datetime(
            2026,
            8,
            27,
            tzinfo=timezone.utc,
        ),
    )

    manager.reconcile_peer(
        conn,
        plan,
    )

    state = conn.execute(
        """
        SELECT state
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["state"] == "paused"

    assert not any(
        call
        and call[0] == SSHFS_BINARY
        for call in calls
    )

    conn.close()


def test_pause_unmounts_only_owned_sshfs(
    tmp_path,
):
    conn = _db(tmp_path)
    plan = _plan()
    root = tmp_path / "mnt"
    target = root / NODE_ID

    conn.execute(
        """
        INSERT INTO mount_preferences (
            peer_node_id,
            desired_state
        )
        VALUES (?, 'paused')
        """,
        (NODE_ID,),
    )
    conn.commit()

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: _mountinfo(
            target
        ),
        mount_root=root,
    )

    manager.reconcile_peer(
        conn,
        plan,
    )

    assert any(
        call[:3]
        == [
            FUSERMOUNT_BINARY,
            "-u",
            "-z",
        ]
        for call in calls
    )

    state = conn.execute(
        """
        SELECT state
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["state"] == "paused"

    conn.close()


def test_foreign_mount_is_never_unmounted(
    tmp_path,
):
    conn = _db(tmp_path)
    plan = _plan()
    root = tmp_path / "mnt"
    target = root / NODE_ID

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: _mountinfo(
            target,
            "ext4",
        ),
        mount_root=root,
    )

    manager.reconcile_peer(
        conn,
        plan,
    )

    assert not any(
        call
        and call[0]
        == FUSERMOUNT_BINARY
        for call in calls
    )

    state = conn.execute(
        """
        SELECT state, error_code
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert tuple(state) == (
        "mount_problem",
        "foreign_mount",
    )

    conn.close()


def test_stale_probe_is_detached_and_backed_off(
    tmp_path,
    monkeypatch,
):
    conn = _db(tmp_path)
    plan = _plan()
    root = tmp_path / "mnt"
    target = root / NODE_ID

    monkeypatch.setenv(
        "LATTICE_CONFIG_PATH",
        str(
            tmp_path / "missing.toml"
        ),
    )

    calls = []

    def runner(command, **kwargs):
        calls.append(command)

        if command[0].endswith(
            "/stat"
        ):
            raise subprocess.TimeoutExpired(
                command,
                5,
            )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: _mountinfo(
            target
        ),
        mount_root=root,
        clock=lambda: datetime(
            2026,
            8,
            27,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    manager.reconcile_peer(
        conn,
        plan,
    )

    state = conn.execute(
        """
        SELECT
            state,
            failure_count,
            error_code,
            next_retry_at
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["state"] == "reconnecting"
    assert state["failure_count"] == 1
    assert state["error_code"] == "probe_timeout"
    assert state["next_retry_at"] is not None

    assert any(
        call[:3]
        == [
            FUSERMOUNT_BINARY,
            "-u",
            "-z",
        ]
        for call in calls
    )

    conn.close()


def test_successful_new_mount_becomes_mounted(
    tmp_path,
):
    conn = _db(tmp_path)
    plan = _plan()
    root = tmp_path / "mnt"
    target = root / NODE_ID

    mounted = {
        "value": False,
    }

    calls = []

    def mountinfo_reader():
        if mounted["value"]:
            return _mountinfo(
                target
            )
        return ""

    def runner(command, **kwargs):
        calls.append(command)

        if command[0] == SSHFS_BINARY:
            mounted["value"] = True

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=mountinfo_reader,
        mount_root=root,
        clock=lambda: datetime(
            2026,
            8,
            27,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    manager.reconcile_peer(
        conn,
        plan,
    )

    state = conn.execute(
        """
        SELECT
            state,
            failure_count,
            error_code
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert tuple(state) == (
        "mounted",
        0,
        None,
    )

    assert any(
        call
        and call[0] == SSHFS_BINARY
        for call in calls
    )

    conn.close()


def test_mount_manager_unit_is_system_level():
    unit = Path(
        "deploy/systemd/"
        "lattice-mount-manager.service"
    ).read_text()

    assert "User=root" in unit
    assert "Group=root" in unit

    assert (
        "lattice.file_access.mount_manager"
        in unit
    )

    assert "PrivateMounts=no" in unit
    assert "PrivateTmp=no" in unit
    assert "ProtectSystem=no" in unit
    assert "ProtectKernelTunables=no" in unit
    assert "ProtectKernelModules=no" in unit
    assert "ProtectControlGroups=no" in unit
    assert "ReadWritePaths=" not in unit

    assert (
        "WantedBy=multi-user.target"
        in unit
    )


def test_tmpfiles_creates_stable_mount_root():
    tmpfiles = Path(
        "deploy/tmpfiles.d/lattice.conf"
    ).read_text()

    assert (
        "d /mnt/lattice"
        in tmpfiles
    )


def test_revoked_owned_mount_is_detached_and_state_removed(
    tmp_path,
):
    conn = _db(tmp_path)
    root = tmp_path / "mnt"
    root.mkdir()
    target = root / NODE_ID
    target.mkdir()

    conn.execute(
        """
        INSERT INTO mount_preferences (
            peer_node_id,
            desired_state
        )
        VALUES (?, 'mounted')
        """,
        (NODE_ID,),
    )

    conn.execute(
        """
        INSERT INTO mount_state (
            peer_node_id,
            state
        )
        VALUES (?, 'mounted')
        """,
        (NODE_ID,),
    )

    conn.commit()

    mounted = {
        "value": True,
    }

    calls = []

    def mountinfo_reader():
        if mounted["value"]:
            return _mountinfo(
                target
            )
        return ""

    def runner(command, **kwargs):
        calls.append(command)

        if (
            command[0]
            == FUSERMOUNT_BINARY
        ):
            mounted["value"] = False

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=mountinfo_reader,
        mount_root=root,
    )

    assert manager.retire_node(
        conn,
        NODE_ID,
    )

    conn.commit()

    assert not target.exists()

    assert conn.execute(
        """
        SELECT 1
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone() is None

    assert conn.execute(
        """
        SELECT 1
        FROM mount_preferences
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone() is None

    conn.close()


def test_revoked_foreign_mount_is_never_touched(
    tmp_path,
):
    conn = _db(tmp_path)
    root = tmp_path / "mnt"
    root.mkdir()
    target = root / NODE_ID
    target.mkdir()

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: _mountinfo(
            target,
            "ext4",
        ),
        mount_root=root,
    )

    assert not manager.retire_node(
        conn,
        NODE_ID,
    )

    conn.commit()

    assert not any(
        call
        and call[0]
        == FUSERMOUNT_BINARY
        for call in calls
    )

    state = conn.execute(
        """
        SELECT state, error_code
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert tuple(state) == (
        "mount_problem",
        "retired_foreign_mount",
    )

    assert target.exists()

    conn.close()


def test_revoked_nonempty_directory_is_not_deleted(
    tmp_path,
):
    conn = _db(tmp_path)
    root = tmp_path / "mnt"
    root.mkdir()
    target = root / NODE_ID
    target.mkdir()
    (target / "unexpected").write_text(
        "keep"
    )

    manager = MountManager(
        mountinfo_reader=lambda: "",
        mount_root=root,
    )

    assert not manager.retire_node(
        conn,
        NODE_ID,
    )

    conn.commit()

    assert (
        target / "unexpected"
    ).read_text() == "keep"

    state = conn.execute(
        """
        SELECT error_code
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["error_code"] == (
        "retired_directory_not_empty"
    )

    conn.close()


def test_mount_ownership_requires_home_export(
    tmp_path,
):
    target = tmp_path / NODE_ID

    entry = MountEntry(
        mount_point=str(
            target.absolute()
        ),
        filesystem_type="fuse.sshfs",
        source=(
            "someone@10.77.0.9:/other"
        ),
    )

    assert not is_lattice_sshfs_mount(
        target,
        entry,
        mount_root=tmp_path,
    )


def test_persistent_mount_problem_creates_only_one_alert(
    tmp_path,
    monkeypatch,
):
    conn = _db(tmp_path)
    plan = _plan()

    monkeypatch.setenv(
        "LATTICE_CONFIG_PATH",
        str(
            tmp_path / "missing.toml"
        ),
    )

    problem_since = (
        "2026-08-27T11:50:00+00:00"
    )

    conn.execute(
        """
        INSERT INTO mount_state (
            peer_node_id,
            state,
            problem_since,
            error_code,
            error_message
        )
        VALUES (
            ?,
            'offline',
            ?,
            'sshfs_failed',
            'peer unavailable'
        )
        """,
        (
            NODE_ID,
            problem_since,
        ),
    )

    conn.commit()

    manager = MountManager(
        mountinfo_reader=lambda: "",
        mount_root=tmp_path / "mnt",
        clock=lambda: datetime(
            2026,
            8,
            27,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    manager._sync_persistent_alert(
        conn,
        plan,
    )

    conn.commit()

    assert conn.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE resolved_at IS NULL
        """
    ).fetchone()[0] == 1

    manager._sync_persistent_alert(
        conn,
        plan,
    )

    conn.commit()

    assert conn.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        """
    ).fetchone()[0] == 1

    state = conn.execute(
        """
        SELECT alert_id
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["alert_id"] is not None

    conn.close()


def test_mount_recovery_resolves_persistent_alert(
    tmp_path,
    monkeypatch,
):
    conn = _db(tmp_path)
    plan = _plan()

    monkeypatch.setenv(
        "LATTICE_CONFIG_PATH",
        str(
            tmp_path / "missing.toml"
        ),
    )

    conn.execute(
        """
        INSERT INTO mount_state (
            peer_node_id,
            state,
            problem_since,
            error_code
        )
        VALUES (
            ?,
            'offline',
            '2026-08-27T11:50:00+00:00',
            'sshfs_failed'
        )
        """,
        (NODE_ID,),
    )

    conn.commit()

    manager = MountManager(
        mountinfo_reader=lambda: "",
        mount_root=tmp_path / "mnt",
        clock=lambda: datetime(
            2026,
            8,
            27,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    manager._sync_persistent_alert(
        conn,
        plan,
    )

    conn.execute(
        """
        UPDATE mount_state
        SET state = 'mounted',
            problem_since = NULL
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    )

    manager._sync_persistent_alert(
        conn,
        plan,
    )

    conn.commit()

    alert = conn.execute(
        """
        SELECT resolved_at
        FROM alerts
        """
    ).fetchone()

    assert alert["resolved_at"] is not None

    state = conn.execute(
        """
        SELECT alert_id, problem_since
        FROM mount_state
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    assert state["alert_id"] is None
    assert state["problem_since"] is None

    conn.close()


def test_mount_alert_schema_is_migration_safe():
    conn = sqlite3.connect(
        ":memory:"
    )

    run_migrations(conn)
    run_migrations(conn)

    columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(mount_state)"
        ).fetchall()
    }

    assert "problem_since" in columns
    assert "alert_id" in columns

    conn.close()


def test_mount_manager_has_manual_wake():
    manager = MountManager(
        mountinfo_reader=lambda: "",
    )

    assert not manager._wake_event.is_set()

    manager.wake()

    assert manager._wake_event.is_set()


def test_new_mount_tries_verified_alternate_route_after_primary_failure(tmp_path):
    conn = _db(tmp_path)
    plan = PeerMountPlan(
        node_id=NODE_ID,
        hostname="worker-node",
        ip="10.77.0.201",
        remote_user="workeruser",
        local_uid=os.getuid() or 1000,
        local_gid=os.getgid(),
        port=22022,
        routes=("10.77.0.201", "10.77.0.202"),
    )
    root = tmp_path / "mnt"
    target = root / NODE_ID
    mounted = {"value": False}
    calls = []

    def mountinfo_reader():
        return _mountinfo(target) if mounted["value"] else ""

    def runner(command, **kwargs):
        calls.append(command)
        if command[0] == SSHFS_BINARY and "10.77.0.201" in command[1]:
            return subprocess.CompletedProcess(command, 1, "", "primary unavailable")
        if command[0] == SSHFS_BINARY and "10.77.0.202" in command[1]:
            mounted["value"] = True
        return subprocess.CompletedProcess(command, 0, "", "")
    manager = MountManager(
        runner=runner,
        mountinfo_reader=mountinfo_reader,
        mount_root=root,
        clock=lambda: datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
    )
    manager.reconcile_peer(conn, plan)
    sshfs_calls = [call for call in calls if call and call[0] == SSHFS_BINARY]
    assert len(sshfs_calls) == 2
    assert "10.77.0.201" in sshfs_calls[0][1]
    assert "10.77.0.202" in sshfs_calls[1][1]
    state = conn.execute(
        "SELECT state, failure_count FROM mount_state WHERE peer_node_id=?",
        (NODE_ID,),
    ).fetchone()
    assert tuple(state) == ("mounted", 0)
    conn.close()


def test_master_detaches_false_green_mount_when_worker_export_is_unhealthy(
    tmp_path, monkeypatch
):
    import lattice.file_access.mount_manager as mount_manager_mod

    conn = _db(tmp_path)
    plan = _plan()
    root = tmp_path / "mnt"
    target = root / NODE_ID
    calls = []

    monkeypatch.setenv("LATTICE_CONFIG_PATH", str(tmp_path / "missing.toml"))
    monkeypatch.setattr(mount_manager_mod, "_local_fleet_role", lambda conn: "master")
    monkeypatch.setattr(
        mount_manager_mod,
        "_peer_file_export_healthy",
        lambda conn, node_id, now: False,
    )

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    manager = MountManager(
        runner=runner,
        mountinfo_reader=lambda: _mountinfo(target),
        mount_root=root,
        clock=lambda: datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
    )

    manager.reconcile_peer(conn, plan)

    state = conn.execute(
        "SELECT state, error_code FROM mount_state WHERE peer_node_id=?",
        (NODE_ID,),
    ).fetchone()
    assert tuple(state) == ("reconnecting", "remote_export_unhealthy")
    assert any(
        call[:3] == [FUSERMOUNT_BINARY, "-u", "-z"] for call in calls
    )
    assert not any(call and call[0] == STAT_BINARY for call in calls)
    conn.close()


def test_master_export_proof_requires_fresh_authenticated_worker_service():
    import lattice.file_access.mount_manager as mount_manager_mod

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE fleet_nodes (node_id TEXT, role TEXT, membership_state TEXT, worker_id INTEGER)"
    )
    conn.execute(
        "CREATE TABLE services (worker_id INTEGER, name TEXT, status TEXT, last_reported_at TEXT)"
    )
    conn.execute(
        "INSERT INTO fleet_nodes VALUES (?, 'worker', 'active', 7)", (NODE_ID,)
    )
    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    conn.execute(
        "INSERT INTO services VALUES (7, 'file_export', 'healthy', ?)",
        ((now).isoformat(),),
    )
    assert mount_manager_mod._peer_file_export_healthy(conn, NODE_ID, now=now)

    conn.execute(
        "UPDATE services SET last_reported_at=? WHERE worker_id=7",
        ((now.replace(minute=59, hour=11)).isoformat(),),
    )
    assert not mount_manager_mod._peer_file_export_healthy(conn, NODE_ID, now=now)

    conn.execute(
        "UPDATE services SET status='unhealthy', last_reported_at=? WHERE worker_id=7",
        (now.isoformat(),),
    )
    assert not mount_manager_mod._peer_file_export_healthy(conn, NODE_ID, now=now)
    conn.close()
