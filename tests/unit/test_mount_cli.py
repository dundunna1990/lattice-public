from types import SimpleNamespace

from lattice.core.db import (
    get_db_connection,
)
from lattice.core.migrations import (
    run_migrations,
)
from lattice.cli.commands import mounts
from lattice import operator_interface


NODE_ID = (
    "11111111-1111-4111-8111-111111111111"
)


def _setup(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "LATTICE_DB_PATH",
        str(
            tmp_path / "mount-cli.db"
        ),
    )

    conn = get_db_connection()
    run_migrations(conn)
    conn.close()


def test_mount_cli_pause_and_resume_are_persistent(
    tmp_path,
    monkeypatch,
):
    _setup(
        tmp_path,
        monkeypatch,
    )

    wakes = []

    monkeypatch.setattr(
        mounts,
        "_wake_manager",
        lambda: wakes.append(True),
    )

    assert mounts.cmd_mounts(
        SimpleNamespace(
            action="unmount",
            peer=NODE_ID,
        )
    ) == 0

    conn = get_db_connection()

    row = conn.execute(
        """
        SELECT desired_state
        FROM mount_preferences
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    conn.close()

    assert row["desired_state"] == "paused"

    assert mounts.cmd_mounts(
        SimpleNamespace(
            action="mount",
            peer=NODE_ID,
        )
    ) == 0

    conn = get_db_connection()

    row = conn.execute(
        """
        SELECT desired_state
        FROM mount_preferences
        WHERE peer_node_id = ?
        """,
        (NODE_ID,),
    ).fetchone()

    conn.close()

    assert row["desired_state"] == "mounted"

    assert len(wakes) == 2


def _seed_active_and_revoked_mount_observations():
    master = "22222222-2222-4222-8222-222222222222"
    active = "33333333-3333-4333-8333-333333333333"
    revoked = "44444444-4444-4444-8444-444444444444"
    conn = get_db_connection()
    for node_id, hostname, role, state in (
        (master, "master-node", "master", "active"),
        (active, "worker-node", "worker", "active"),
        (revoked, "worker-node", "worker", "revoked"),
    ):
        conn.execute(
            """INSERT INTO fleet_nodes(
                   node_id,hostname,role,main_user,main_uid,main_gid,membership_state
               ) VALUES(?,?,?,?,?,?,?)""",
            (node_id, hostname, role, "user", 1000, 1000, state),
        )
    for observer, peer, reported in (
        (master, active, "2026-09-23T08:00:00+00:00"),
        (active, master, "2026-09-23T08:00:00+00:00"),
        (master, revoked, "2026-09-03T08:00:00+00:00"),
        (revoked, master, "2026-09-03T08:00:00+00:00"),
    ):
        conn.execute(
            """INSERT INTO mount_observations(
                   observer_node_id,peer_node_id,state,last_reported_at
               ) VALUES(?,?, 'mounted', ?)""",
            (observer, peer, reported),
        )
    conn.commit()
    conn.close()
    return master, active


def test_fleet_mount_status_excludes_revoked_node_history(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    master, active = _seed_active_and_revoked_mount_observations()

    cli_rows = [dict(row) for row in mounts._fleet_rows()]
    operator_rows = operator_interface._mounts_fleet()

    expected = {(master, active), (active, master)}
    assert {
        (row["observer_node_id"], row["peer_node_id"])
        for row in cli_rows
    } == expected
    assert {
        (row["observer_node_id"], row["peer_node_id"])
        for row in operator_rows
    } == expected


def test_mount_cli_rejects_hostname_as_identity(
    tmp_path,
    monkeypatch,
):
    _setup(
        tmp_path,
        monkeypatch,
    )

    result = mounts.cmd_mounts(
        SimpleNamespace(
            action="mount",
            peer="worker-node",
        )
    )

    assert result == 1


def test_system_status_tracks_mount_manager():
    from pathlib import Path

    text = Path(
        "lattice/cli/commands/system.py"
    ).read_text()

    assert (
        "lattice-mount-manager"
        in text
    )

    assert (
        "lattice-file-sshd"
        in text
    )
