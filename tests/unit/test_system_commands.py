from types import SimpleNamespace

from lattice.cli.commands import system as system_cmd
from lattice.wizard.lifecycle import RoleLifecycleError


def test_restart_returns_failure_when_role_resolution_fails(monkeypatch):
    def fail(_target):
        raise RoleLifecycleError("role unavailable")

    monkeypatch.setattr(system_cmd, "_resolve_targets", fail)

    assert system_cmd._restart("master") == 1


def test_restart_returns_failure_when_systemctl_fails(monkeypatch):
    monkeypatch.setattr(
        system_cmd,
        "_resolve_targets",
        lambda _target: ["lattice-master"],
    )
    monkeypatch.setattr(
        system_cmd,
        "_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="permission denied",
        ),
    )

    assert system_cmd._restart("master") == 1


def test_restart_returns_success_when_systemctl_succeeds(monkeypatch):
    monkeypatch.setattr(
        system_cmd,
        "_resolve_targets",
        lambda _target: ["lattice-master"],
    )
    monkeypatch.setattr(
        system_cmd,
        "_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )

    assert system_cmd._restart("master") == 0


def test_cmd_system_propagates_restart_failure(monkeypatch):
    monkeypatch.setattr(system_cmd, "_restart", lambda _target: 1)

    args = SimpleNamespace(
        action="restart",
        target="master",
        n=100,
        follow=False,
    )

    assert system_cmd.cmd_system(args) == 1
