import subprocess

import pytest

from lattice.ip_change.pool import (
    AddressPool,
    AddressPoolError,
    choose_available_address,
    find_contiguous_available_pool,
    read_address_pool,
    suggested_pool,
    write_address_pool,
)


def test_master_gets_a_small_automatic_pool_on_a_normal_home_network():
    pool = suggested_pool("10.77.0.44", 24, "10.77.0.1", "enp3s0")

    assert pool.start == "10.77.0.200"
    assert pool.end == "10.77.0.220"
    assert pool.gateway == "10.77.0.1"


def test_allocator_skips_reserved_and_network_in_use_addresses():
    pool = AddressPool(
        network="10.77.0.0/24",
        start="10.77.0.200",
        end="10.77.0.202",
        gateway="10.77.0.1",
        prefix=24,
        dns=("10.77.0.1",),
        interface="enp3s0",
    )

    selected = choose_available_address(
        pool,
        {"10.77.0.200"},
        lambda address: address == "10.77.0.201",
    )

    assert selected == "10.77.0.202"


def test_allocator_reports_each_live_probe_to_progress_callback():
    pool = AddressPool(
        network="10.77.0.0/24",
        start="10.77.0.200",
        end="10.77.0.202",
        gateway="10.77.0.1",
        prefix=24,
        dns=("10.77.0.1",),
        interface="enp3s0",
    )
    checked = []

    selected = choose_available_address(
        pool,
        {"10.77.0.200"},
        lambda address: address == "10.77.0.201",
        on_check=checked.append,
    )

    assert checked == ["10.77.0.201", "10.77.0.202"]
    assert selected == "10.77.0.202"


def test_pool_is_saved_and_readable_by_the_master_daemon(monkeypatch, tmp_path):
    path = tmp_path / "address-pool.json"
    monkeypatch.setenv("LATTICE_ADDRESS_POOL_PATH", str(path))
    pool = suggested_pool("10.77.0.44", 24, "10.77.0.1", "enp3s0")

    write_address_pool(pool)

    assert read_address_pool() == pool
    assert path.stat().st_mode & 0o777 == 0o644



def test_live_scan_builds_pool_only_from_a_contiguous_free_block():
    occupied = {"10.77.0.202", "10.77.0.203"}
    checked = []
    pool = find_contiguous_available_pool(
        "10.77.0.94", 24, "10.77.0.254", "wlan0",
        lambda address: address in occupied,
        dns=("10.77.0.254", "1.1.1.1"), size=5, on_check=checked.append,
    )
    assert pool.start == "10.77.0.204"
    assert pool.end == "10.77.0.208"
    assert pool.dns == ("10.77.0.254", "1.1.1.1")
    assert "10.77.0.202" in checked and "10.77.0.208" in checked


def test_live_scan_refuses_when_no_contiguous_block_exists():
    occupied = {"10.77.0.3", "10.77.0.5"}
    with pytest.raises(AddressPoolError, match="No contiguous block"):
        find_contiguous_available_pool(
            "10.77.0.2", 29, "10.77.0.1", "wlan0",
            lambda address: address in occupied,
            size=3,
        )
