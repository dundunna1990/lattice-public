# tests/unit/test_mdns.py
import pytest
from unittest.mock import patch

from lattice.core import mdns
from lattice.core.mdns import _parse_avahi_output, discover_waiting_workers

def test_parse_avahi_output_with_spaces():
    """Test mDNS parser handles spaces and quotes in TXT records."""
    # Sample avahi-browse -p output with a TXT record containing spaces
    sample_output = '''=;eth0;IPv4;lattice-worker;_lattice._tcp;local;backup-node.local;10.77.0.85;9999;"role=worker" "ssh_user=masteruser doe" "version=0.4.0"
'''
    workers = _parse_avahi_output(sample_output)
    assert len(workers) == 1
    worker = workers[0]
    assert worker["host"] == "backup-node.local"
    assert worker["addr"] == "10.77.0.85"
    assert worker["port"] == 9999
    # Check that the TXT parser preserved the space in ssh_user
    assert worker["txt"].get("ssh_user") == "masteruser doe"


def test_discover_waiting_workers_ignores_nonwaiting_hosts():
    sample_output = (
        '=;eth0;IPv4;waiting;_lattice._tcp;local;waiting-node.local;10.77.0.85;9999;'
        '"role=worker" "state=waiting" "pairing_id=pair-123"\n'
        '=;eth0;IPv4;paired;_lattice._tcp;local;worker-node.local;10.77.0.103;9999;'
        '"role=worker" "state=paired" "pairing_id=pair-456"\n'
    )

    class Result:
        stdout = sample_output

    with patch("lattice.core.mdns.subprocess.run", return_value=Result()):
        with patch("lattice.core.mdns._is_reachable", return_value=True):
            workers = discover_waiting_workers()

    assert len(workers) == 1
    assert workers[0]["host"] == "waiting-node.local"


def test_write_service_file_is_readable_by_avahi(tmp_path, monkeypatch):
    service_file = tmp_path / "lattice.service"
    monkeypatch.setattr(mdns, "SERVICE_FILE", str(service_file))

    mdns.write_service_file(
        "Lattice Worker worker-node (waiting)",
        9999,
        {"role": "worker", "state": "waiting", "pairing_id": "pair-123"},
    )

    assert service_file.stat().st_mode & 0o777 == 0o644
    text = service_file.read_text()
    assert "<type>_lattice._tcp</type>" in text
    assert "<txt-record>state=waiting</txt-record>" in text
