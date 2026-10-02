"""Regression checks for the final independent-audit follow-ups."""

from pathlib import Path

import pytest

from lattice.core.release_convergence import (
    ReleaseConvergenceError,
    verify_active_release,
)
from lattice.core.runtime_environment import (
    RuntimeEnvironmentError,
    validate_production_path_overrides,
)


def test_peer_home_access_is_documented_as_intentionally_read_write():
    readme = Path("README.md").read_text()
    assert "intentionally read/write" in readme
    assert "changes that peer's real Home directory" in readme
    assert "read-only operator interface" in readme


def test_live_worker_health_uses_critical_component_snapshot():
    api = Path("lattice/daemon/api/worker_app.py").read_text()
    master = Path("lattice/master/health_check.py").read_text()
    assert "HealthChecker().current_snapshot" in api
    assert 'endpoint_status in {"healthy", "degraded"}' in master
    assert "endpoint_degraded" in master
    assert "service_degraded=service_degraded" in master


def test_public_health_response_does_not_expose_component_details():
    source = Path("lattice/daemon/api/worker_app.py").read_text()
    start = source.index('@app.get("/v1/health")')
    end = source.index('@app.get("/v1/pairing/status")')
    route = source[start:end]
    assert '"status": snapshot["status"]' in route
    assert '"services"' not in route
    assert '"mount_observations"' not in route
    assert "**snapshot" not in route


def test_unhandled_per_worker_health_task_errors_are_logged():
    source = Path("lattice/master/health_check.py").read_text()
    assert "results = await asyncio.gather" in source
    assert "Unhandled health task failure" in source
    assert "result.__traceback__" in source


def test_worker_revocation_wakes_shell_only_after_new_mount_plan_is_written():
    source = Path("lattice/cli/commands/workers.py").read_text()
    plan = source.index("write_mount_plan(candidate.manifest, plan)")
    wake = source.index("_wake_shell_manager_after_membership_change(output=output)")
    assert plan < wake
    assert "--signal=SIGUSR1" in source
    assert "lattice-shell-connection-manager.service" in source


def test_installer_preflight_blocks_trusted_shell_and_non_git_sources():
    source = Path("deploy/host-state.sh").read_text()
    assert 'server_port" == "22023"' in source
    assert "normal admin/recovery SSH on port 22" in source
    assert '[[ ! -d "$source_root/.git" ]]' in source
    assert "requires a complete Git checkout" in source


def test_runtime_services_prove_active_release_after_restart():
    for unit in (
        "lattice-master.service",
        "lattice-worker.service",
        "lattice-file-sshd.service",
        "lattice-shell-sshd.service",
        "lattice-mount-manager.service",
        "lattice-shell-connection-manager.service",
    ):
        text = Path("deploy/systemd", unit).read_text()
        assert "lattice.core.release_convergence" in text


def test_release_convergence_accepts_matching_release(tmp_path):
    active = tmp_path / "release"
    module = active / "venv/lib/python/site-packages/lattice/core/release_convergence.py"
    prefix = active / "venv"
    module.parent.mkdir(parents=True)
    prefix.mkdir(exist_ok=True)
    module.write_text("# test\n")
    link = tmp_path / "lattice"
    link.symlink_to(active, target_is_directory=True)
    assert verify_active_release(
        active_root=link,
        module_path=module,
        venv_prefix=prefix,
    ) == active.resolve()


def test_release_convergence_rejects_old_venv(tmp_path):
    active = tmp_path / "new"
    old = tmp_path / "old"
    module = active / "venv/site/lattice/core/release_convergence.py"
    prefix = old / "venv"
    module.parent.mkdir(parents=True)
    prefix.mkdir(parents=True)
    module.write_text("# test\n")
    link = tmp_path / "lattice"
    link.symlink_to(active, target_is_directory=True)
    with pytest.raises(ReleaseConvergenceError, match="virtual environment"):
        verify_active_release(
            active_root=link,
            module_path=module,
            venv_prefix=prefix,
        )


def test_source_tree_allows_test_path_overrides(tmp_path):
    validate_production_path_overrides(
        environ={"LATTICE_DB_PATH": str(tmp_path / "test.sqlite")},
        module_path=tmp_path / "checkout/lattice/core/runtime_environment.py",
    )


def test_installed_runtime_accepts_only_canonical_path_overrides():
    validate_production_path_overrides(
        environ={
            "LATTICE_CONFIG_PATH": "/etc/lattice/lattice.toml",
            "LATTICE_DB_PATH": "/var/lib/lattice/state.sqlite",
            "LATTICE_SOCKET_PATH": "/run/lattice/master.sock",
        },
        module_path=Path(
            "/opt/lattice-releases/20260903T000000Z-1/"
            "lattice/core/runtime_environment.py"
        ),
    )


def test_installed_runtime_rejects_test_only_path_override():
    with pytest.raises(RuntimeEnvironmentError, match="LATTICE_DB_PATH"):
        validate_production_path_overrides(
            environ={"LATTICE_DB_PATH": "/tmp/test.sqlite"},
            module_path=Path(
                "/opt/lattice-releases/20260903T000000Z-1/"
                "lattice/core/runtime_environment.py"
            ),
        )
