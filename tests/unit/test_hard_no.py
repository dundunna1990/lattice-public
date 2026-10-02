"""
Unit tests for the hard no-heal list.
"""
import pytest
from lattice.healing.hard_no import (
    HARD_NO_CATEGORIES,
    FORBIDDEN_COMMANDS,
    is_autoheal_action_allowed,
    is_hard_no,
)

def test_is_hard_no_service_match():
    assert is_hard_no("restart", "sshd") is True
    assert is_hard_no("restart", "ssh") is True
    assert is_hard_no("restart", "sudo") is True
    assert is_hard_no("restart", "ufw") is True
    assert is_hard_no("restart", "iptables") is True
    assert is_hard_no("restart", "NetworkManager") is True
    assert is_hard_no("restart", "apt") is True
    assert is_hard_no("restart", "kernel") is True
    assert is_hard_no("restart", "syncthing") is False  # allowed

def test_is_hard_no_action_match():
    assert is_hard_no("systemctl restart sshd") is True
    assert is_hard_no("systemctl restart NetworkManager") is True
    assert is_hard_no("apt install something") is True
    assert is_hard_no("chmod 777 /") is True
    assert is_hard_no("systemctl restart syncthing", "syncthing") is False


def test_autoheal_policy_allows_only_lattice_services():
    assert is_autoheal_action_allowed("restart", "lattice-worker.service") is True
    assert is_autoheal_action_allowed("restart", "lattice-master") is False
    assert is_autoheal_action_allowed("status", "lattice-worker.service") is False
    assert is_autoheal_action_allowed("restart", "lattice-daemon") is False
    assert is_autoheal_action_allowed("restart", "sshd") is False
    assert is_autoheal_action_allowed("restart", "syncthing") is False
    assert is_autoheal_action_allowed("flush", "lattice-worker") is False

def test_hard_no_list():
    from lattice.healing.hard_no import get_hard_no_list
    lst = get_hard_no_list()
    assert "sshd" in lst
    assert "ufw" in lst
    assert "kernel" in lst
