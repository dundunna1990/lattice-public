from pathlib import Path

from lattice.core import bootstrap_prepare


def test_runtime_lock_ownership_is_repaired_after_uid_change(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "run" / "lattice"
    state_dir = tmp_path / "var" / "lib" / "lattice"
    runtime_dir.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    ip_lock = runtime_dir / "ip_monitor.lock"
    plan_lock = runtime_dir / "mount-plans.lock"
    plan = state_dir / "mount-plans.json"
    for path in (ip_lock, plan_lock, plan):
        path.write_text("stale")

    mapped = {
        "/run/lattice/ip_monitor.lock": ip_lock,
        "/run/lattice/mount-plans.lock": plan_lock,
        "/var/lib/lattice/mount-plans.json": plan,
    }
    monkeypatch.setattr(
        bootstrap_prepare, "Path", lambda value: mapped.get(value, Path(value))
    )

    calls = []
    monkeypatch.setattr(bootstrap_prepare.os, "chown", lambda path, uid, gid: calls.append(("chown", path, uid, gid)))
    monkeypatch.setattr(bootstrap_prepare.os, "chmod", lambda path, mode: calls.append(("chmod", path, mode)))

    bootstrap_prepare._repair_runtime_files(997, 997)

    for path in (ip_lock, plan_lock, plan):
        assert ("chown", path, 997, 997) in calls
    assert ("chmod", ip_lock, 0o640) in calls
    assert ("chmod", plan_lock, 0o640) in calls
    assert ("chmod", plan, 0o600) in calls


def test_purge_uninstall_removes_disposable_runtime_directory():
    uninstall = Path("deploy/uninstall.sh").read_text()
    assert "/run/lattice" in uninstall
    purge_block = uninstall[uninstall.index('if [[ "$PURGE" == "true" ]]'): ]
    assert "rm -rf /var/lib/lattice /var/log/lattice /etc/lattice /run/lattice" in purge_block
    assert 'if [[ "$HOST_STATE_RESTORE_OK" == "true" ]]' in purge_block
    assert "rm -rf /var/lib/lattice-root" in purge_block
    assert "preserved /var/lib/lattice-root" in purge_block


def test_tui_labels_system_uptime_separately_from_daemon_status():
    source = Path("lattice/cli/tui.py").read_text()
    assert "Master daemon" in source
    assert 'Uptime      {current.uptime}' in source
    assert '(uptime:' not in source
