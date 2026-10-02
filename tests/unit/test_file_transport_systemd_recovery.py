from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "deploy" / "systemd"

REQUEST = "/var/lib/lattice/file-transport-request.json"

RUNTIME_PREFLIGHT = (
    "ExecStartPre=/usr/bin/install -d -o root -g root "
    "-m 0755 /run/sshd"
)


def _unit(name: str) -> str:
    return (SYSTEMD / name).read_text(encoding="utf-8")


def test_file_transport_reconcile_retries_without_start_limit_lockout():
    text = _unit("lattice-file-transport-reconcile.service")

    assert "StartLimitIntervalSec=0" in text
    assert "Restart=on-failure" in text
    assert "RestartSec=30s" in text
    assert "RestartSec=0" not in text


def test_file_transport_reconcile_requires_pending_request():
    text = _unit("lattice-file-transport-reconcile.service")

    assert f"ConditionPathExists={REQUEST}" in text


def test_file_transport_reconcile_prepares_openssh_runtime_directory():
    text = _unit("lattice-file-transport-reconcile.service")

    assert RUNTIME_PREFLIGHT in text

    assert text.index(RUNTIME_PREFLIGHT) < text.index(
        "ExecStart=/opt/lattice/bin/lattice-file-transport-exec"
    )


def test_file_sshd_prepares_runtime_directory_before_validation():
    text = _unit("lattice-file-sshd.service")

    validation = (
        "ExecStartPre=/usr/sbin/sshd -t "
        "-f /etc/lattice/file-ssh/sshd_config"
    )

    assert RUNTIME_PREFLIGHT in text
    assert validation in text
    assert text.index(RUNTIME_PREFLIGHT) < text.index(validation)


def test_file_transport_path_does_not_hot_loop_on_unchanged_failure():
    text = _unit("lattice-file-transport-reconcile.path")

    assert f"PathChanged={REQUEST}" in text
    assert f"PathExists={REQUEST}" not in text

    assert (
        "Unit=lattice-file-transport-reconcile.service"
    ) in text


def test_path_start_checks_for_request_surviving_reboot():
    text = _unit("lattice-file-transport-reconcile.path")

    assert (
        "Wants=lattice-file-transport-reconcile.service"
    ) in text
