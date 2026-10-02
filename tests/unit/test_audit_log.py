"""
Unit tests for the hash‑chained audit log.
"""
import pytest
import json
import tempfile
from pathlib import Path
from lattice.healing.audit_log import AuditLog

def test_append_and_read():
    """Test appending entries and reading them."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.log"
        audit = AuditLog(log_path)
        # Append first entry
        entry1 = {"action": "restart", "service": "syncthing"}
        assert audit.append(entry1) is True
        # Append second entry
        entry2 = {"action": "restart", "service": "sshd"}
        assert audit.append(entry2) is True

        entries = audit.read_entries()
        assert len(entries) == 2
        assert entries[0]["data"] == entry1
        assert entries[1]["data"] == entry2
        # Check hashes
        assert "hash" in entries[0]
        assert "hash" in entries[1]
        # Check chaining
        assert entries[1].get("prev_hash") == entries[0]["hash"]
        assert entries[0].get("prev_hash") is None

def test_verify_chain():
    """Test that chain verification works."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.log"
        audit = AuditLog(log_path)
        audit.append({"action": "restart", "service": "syncthing"})
        audit.append({"action": "restart", "service": "sshd"})
        assert audit.verify_chain() is True

def test_tampered_log_fails_verification():
    """Test that tampering is detected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.log"
        audit = AuditLog(log_path)
        audit.append({"action": "restart", "service": "syncthing"})
        audit.append({"action": "restart", "service": "sshd"})

        # Tamper: modify the first entry's data
        with open(log_path, 'r') as f:
            lines = f.readlines()
        # Parse first entry, modify, write back
        entry = json.loads(lines[0].strip())
        entry["data"]["service"] = "tampered"
        lines[0] = json.dumps(entry) + "\n"
        with open(log_path, 'w') as f:
            f.writelines(lines)

        assert audit.verify_chain() is False

def test_append_after_tamper_detected():
    """Appending after tampering fails closed and leaves the file unchanged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.log"
        audit = AuditLog(log_path)
        audit.append({"action": "restart", "service": "syncthing"})
        # Tamper
        with open(log_path, 'r') as f:
            lines = f.readlines()
        entry = json.loads(lines[0].strip())
        entry["data"]["service"] = "tampered"
        lines[0] = json.dumps(entry) + "\n"
        with open(log_path, 'w') as f:
            f.writelines(lines)
        damaged = log_path.read_bytes()
        assert audit.append({"action": "restart", "service": "sshd"}) is False
        assert log_path.read_bytes() == damaged
        assert audit.verify_chain() is False


def test_symlinked_audit_log_is_refused(tmp_path):
    target = tmp_path / "target.log"
    target.write_text("do not touch\n")
    link = tmp_path / "audit.log"
    link.symlink_to(target)

    assert AuditLog(link).append({"action": "restart"}) is False
    assert target.read_text() == "do not touch\n"


def test_normal_append_uses_cached_head_without_full_rescan(tmp_path):
    """After trust is established, normal appends inspect only the tail."""
    from unittest.mock import patch

    log_path = tmp_path / "audit.log"
    audit = AuditLog(log_path)

    assert audit.append(
        {"action": "restart", "service": "one"}
    ) is True

    with patch.object(
        audit,
        "_verify_lines",
        side_effect=AssertionError(
            "normal append unexpectedly rescanned full history"
        ),
    ):
        assert audit.append(
            {"action": "restart", "service": "two"}
        ) is True

    assert audit.verify_chain() is True
