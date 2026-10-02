from pathlib import Path
import sqlite3

from lattice.backup.preflight import (
    BackupPreflightReport,
    FIRST_BACKUP_CONFIRM_BYTES,
    GIB,
    evaluate_preflight,
    record_successful_preflight,
    scan_source,
    _baseline,
)
from lattice.core.migrations import run_migrations


def _report(size, *, mounts=(), dirs=None):
    return BackupPreflightReport(
        included_bytes=size,
        logical_bytes=size,
        mount_targets=tuple(mounts),
        directory_sizes=dict(dirs or {}),
    )


def test_scan_source_prunes_excludes_and_cache_markers(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "keep.txt").write_bytes(b"k" * 100)
    cache = home / "cache"
    cache.mkdir()
    (cache / "junk.bin").write_bytes(b"x" * 1000)

    modules = home / "project" / "node_modules"
    modules.mkdir(parents=True)
    (modules / "dep.bin").write_bytes(b"y" * 1000)

    venv = home / "custom-env"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home=/usr/bin")
    (venv / "payload.bin").write_bytes(b"z" * 1000)

    monkeypatch.setattr(
        "lattice.backup.preflight.mounts_under",
        lambda _source: (),
    )
    result = scan_source(
        home,
        [home / "cache", home / "**/node_modules"],
    )

    assert result.logical_bytes == 100
    assert result.mount_targets == ()
def test_preflight_blocks_new_mount():
    previous = {
        "included_bytes": 10 * GIB,
        "mount_targets": (),
        "directory_sizes": {},
    }
    result = evaluate_preflight(
        _report(10 * GIB, mounts=("/home/user/External",)),
        previous=previous,
        established=True,
        target_total_bytes=500 * GIB,
        target_free_bytes=400 * GIB,
    )
    assert any("New mount" in value for value in result.blockers)


def test_preflight_blocks_destination_capacity_for_unestablished_backup():
    result = evaluate_preflight(
        _report(60 * GIB),
        previous=None,
        established=False,
        target_total_bytes=100 * GIB,
        target_free_bytes=70 * GIB,
    )
    assert any("50%" in value for value in result.blockers)


def test_established_incremental_uses_growth_not_full_source_size():
    previous = {"included_bytes": 100 * GIB, "mount_targets": (), "directory_sizes": {}}
    result = evaluate_preflight(
        _report(100 * GIB),
        previous=previous,
        established=True,
        target_total_bytes=1000 * GIB,
        target_free_bytes=100 * GIB,
    )
    assert result.blockers == ()


def test_initial_mount_layout_is_not_treated_as_new_mount_blocker():
    result = evaluate_preflight(
        _report(10 * GIB, mounts=("/home/user/ExcludedMount",)),
        previous=None,
        established=True,
        target_total_bytes=500 * GIB,
        target_free_bytes=400 * GIB,
    )
    assert not any("New mount" in value for value in result.blockers)
    assert any("Initial mount layout" in value for value in result.warnings)
def test_large_first_backup_requires_explicit_confirmation():
    size = FIRST_BACKUP_CONFIRM_BYTES + GIB
    blocked = evaluate_preflight(
        _report(size),
        previous=None,
        established=False,
        target_total_bytes=1000 * GIB,
        target_free_bytes=900 * GIB,
    )
    assert blocked.requires_confirmation is True

    allowed = evaluate_preflight(
        _report(size),
        previous=None,
        established=False,
        target_total_bytes=1000 * GIB,
        target_free_bytes=900 * GIB,
        allow_large_first_backup=True,
    )
    assert allowed.requires_confirmation is False
    assert any("explicitly confirmed" in value for value in allowed.warnings)


def test_growth_explosion_and_new_large_directory_block():
    previous = {
        "included_bytes": 40 * GIB,
        "mount_targets": (),
        "directory_sizes": {"Documents": 10 * GIB},
    }
    result = evaluate_preflight(
        _report(
            150 * GIB,
            dirs={"Documents": 10 * GIB, "Unexpected": 40 * GIB},
        ),
        previous=previous,
        established=True,
        target_total_bytes=1000 * GIB,
        target_free_bytes=900 * GIB,
    )
    assert any("3x" in value for value in result.blockers)
    assert any("100 GiB" in value for value in result.blockers)
    assert any("New directory over 30 GiB" in value for value in result.blockers)


def test_growth_warning_does_not_block():
    previous = {
        "included_bytes": 20 * GIB,
        "mount_targets": (),
        "directory_sizes": {"Documents": 10 * GIB},
    }
    result = evaluate_preflight(
        _report(35 * GIB, dirs={"Documents": 20 * GIB}),
        previous=previous,
        established=True,
        target_total_bytes=1000 * GIB,
        target_free_bytes=900 * GIB,
    )
    assert result.blockers == ()
    assert any("1.5x" in value for value in result.warnings)
def test_successful_preflight_baseline_round_trip(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = "11111111-1111-4111-8111-111111111111"
    target_node = "22222222-2222-4222-8222-222222222222"
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?,?)""",
        (node, "source", "worker", "source", 1000, 1000, "active"),
    )
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?,?)""",
        (target_node, "target", "worker", "target", 1000, 1000, "active"),
    )
    conn.execute(
        """INSERT INTO backup_targets(
               target_uuid,friendly_name,host_node_id,filesystem_uuid,
               repository_root,target_type)
           VALUES(?,?,?,?,?,?)""",
        ("33333333-3333-4333-8333-333333333333", "Drive", target_node, "disk", "/tmp/repo", "local_storage"),
    )
    target_id = conn.execute("SELECT id FROM backup_targets").fetchone()[0]
    conn.execute(
        """INSERT INTO backup_jobs(
               job_uuid,source_node_id,target_id,source_path)
           VALUES(?,?,?,?)""",
        ("44444444-4444-4444-8444-444444444444", node, target_id, "/home/source"),
    )
    job_id = conn.execute("SELECT id FROM backup_jobs").fetchone()[0]
    conn.commit()
    conn.close()

    report = _report(
        12 * GIB,
        mounts=("/home/source/External",),
        dirs={"Documents": 8 * GIB},
    )
    record_successful_preflight(job_id, report)
    saved = _baseline(job_id)

    assert saved["included_bytes"] == 12 * GIB
    assert saved["mount_targets"] == ("/home/source/External",)
    assert saved["directory_sizes"]["Documents"] == 8 * GIB
