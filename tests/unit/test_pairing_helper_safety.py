"""The privileged pairing helper refuses linked state and destination files."""

import os
from pathlib import Path
import runpy

import pytest


def test_pairing_helper_safe_read_does_not_follow_symlink(tmp_path):
    namespace = runpy.run_path("deploy/lattice-pairing-exec")
    target = tmp_path / "target.json"
    target.write_text("{}\n")
    link = tmp_path / "pairing.json"
    link.symlink_to(target)

    with pytest.raises(SystemExit):
        namespace["safe_read"](link, expected_uid=os.getuid(), max_bytes=1024)


def test_pairing_helper_refuses_linked_authorized_keys_destination(tmp_path):
    namespace = runpy.run_path("deploy/lattice-pairing-exec")
    target = tmp_path / "personal"
    target.write_text("keep\n")
    link = tmp_path / "authorized_keys"
    link.symlink_to(target)

    with pytest.raises(SystemExit):
        namespace["atomic_write"](link, "replace\n", 0o600, os.getuid(), os.getgid())
    assert target.read_text() == "keep\n"
