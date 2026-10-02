from pathlib import Path

from lattice.core.self_check import (
    AUDIT_CRITICAL_BYTES,
    AUDIT_WARN_BYTES,
    audit_log_capacity,
)


def test_master_uses_journald_without_private_rotating_handler():
    source = Path("lattice/daemon/main.py").read_text()
    assert "logging.basicConfig(level=logging.INFO)" in source
    assert "RotatingFileHandler" not in source
    assert "master.log" not in source


def test_master_service_has_no_unsupported_sighup_reload():
    unit = Path("deploy/systemd/lattice-master.service").read_text()
    assert "ExecReload=" not in unit
    assert "-HUP" not in unit


def test_lattice_no_longer_ships_generic_logrotate_rule():
    assert not Path("deploy/logrotate.d/lattice").exists()
    installer = Path("deploy/install.sh").read_text()
    assert "rm -f /etc/logrotate.d/lattice" in installer
    assert "systemctl reload lattice-master.service" not in installer


def test_audit_capacity_warns_before_hard_limit(tmp_path):
    audit = tmp_path / "heal_audit.log"
    audit.write_bytes(b"x")
    assert audit_log_capacity(audit) == (1, None)
    with audit.open("r+b") as handle:
        handle.truncate(AUDIT_WARN_BYTES)
    assert audit_log_capacity(audit)[1] == "warn"
    with audit.open("r+b") as handle:
        handle.truncate(AUDIT_CRITICAL_BYTES)
    assert audit_log_capacity(audit)[1] == "error"
