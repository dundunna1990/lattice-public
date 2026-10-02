from datetime import datetime, timedelta, timezone

import pytest

import lattice.ip_change.reconcile as reconcile


def _policy():
    return {
        "schema_version": 1,
        "role": "master",
        "node_id": "node",
        "address": "10.77.0.200",
        "prefix": 24,
        "network": "10.77.0.0/24",
        "gateway": "10.77.0.254",
        "gateway_mac": "aa:bb:cc:dd:ee:ff",
        "dns": ["10.77.0.254"],
    }


def _active(actual="10.77.0.88"):
    return {
        "interface": "wlan0",
        "connection": "home",
        "connection_uuid": "uuid",
        "connection_type": "802-11-wireless",
        "actual": actual,
        "prefix": 24,
    }

def _base(monkeypatch, status=None):
    monkeypatch.setattr(reconcile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reconcile, "_load_policy", lambda: _policy())
    monkeypatch.setattr(reconcile, "_role", lambda: "master")
    monkeypatch.setattr(reconcile, "_target_owners", lambda target, runner: [])
    monkeypatch.setattr(reconcile, "_trusted_active_path", lambda policy, runner: _active())
    monkeypatch.setattr(reconcile, "_read_status", lambda: status or {})
    written = []
    monkeypatch.setattr(
        reconcile,
        "_write_status",
        lambda state, **fields: written.append({"status": state, **fields}) or written[-1],
    )
    return written


def test_healthy_address_never_changes_network(monkeypatch):
    written = _base(monkeypatch)
    monkeypatch.setattr(
        reconcile, "_trusted_active_path", lambda policy, runner: _active("10.77.0.200")
    )
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("must not apply"))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "healthy"
    assert written[-1]["actual"] == "10.77.0.200"

def test_drift_waits_for_grace_period(monkeypatch):
    written = _base(monkeypatch)
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("too early"))
    now = datetime.now(timezone.utc)
    result = reconcile.reconcile_once(now=now)
    assert result["status"] == "drift_pending"
    assert result["expected"] == "10.77.0.200"
    assert result["actual"] == "10.77.0.88"
    assert written[-1]["first_seen"] == now.isoformat()


def test_unknown_network_fails_closed(monkeypatch):
    written = _base(monkeypatch)
    monkeypatch.setattr(
        reconcile,
        "_trusted_active_path",
        lambda policy, runner: (_ for _ in ()).throw(
            reconcile.NetworkReconcileError("gateway fingerprint mismatch")
        ),
    )
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("must not apply"))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "unsafe_network"
    assert "fingerprint" in result["error"]

def test_duplicate_target_refuses_repair(monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    written = _base(
        monkeypatch,
        {"status": "drift_pending", "expected": "10.77.0.200",
         "actual": "10.77.0.88", "interface": "wlan0", "first_seen": old.isoformat()},
    )
    monkeypatch.setattr(reconcile, "is_address_available", lambda *a, **k: False)
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("must not apply"))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "repair_failed"
    assert "already in use" in result["error"]
    assert written[-1]["actual"] == "10.77.0.88"


def test_successful_repair_is_verified(monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    written = _base(
        monkeypatch,
        {"status": "drift_pending", "expected": "10.77.0.200",
         "actual": "10.77.0.88", "interface": "wlan0", "first_seen": old.isoformat()},
    )
    monkeypatch.setattr(reconcile, "is_address_available", lambda *a, **k: True)
    monkeypatch.setattr(reconcile, "_service_active", lambda *a, **k: True)
    applied = []
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda plan, **k: applied.append(plan))
    checks = iter([_active(), _active("10.77.0.200")])
    monkeypatch.setattr(reconcile, "_trusted_active_path", lambda policy, runner: next(checks))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "repaired"
    assert applied and applied[0].address == "10.77.0.200"
    assert written[-1]["previous_actual"] == "10.77.0.88"


def test_postcheck_failure_rolls_back(monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    _base(
        monkeypatch,
        {"status": "drift_pending", "expected": "10.77.0.200",
         "actual": "10.77.0.88", "interface": "wlan0", "first_seen": old.isoformat()},
    )
    monkeypatch.setattr(reconcile, "is_address_available", lambda *a, **k: True)
    calls = iter([True, False])
    monkeypatch.setattr(reconcile, "_service_active", lambda *a, **k: next(calls))
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: None)
    rolled = []
    monkeypatch.setattr(reconcile, "_rollback_committed_change", lambda *a, **k: rolled.append(True))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "repair_failed"
    assert rolled == [True]

def test_existing_local_owner_prevents_duplicate_assignment(monkeypatch):
    written = _base(monkeypatch)
    monkeypatch.setattr(reconcile, "_target_owners", lambda target, runner: ["wlan0"])
    monkeypatch.setattr(
        reconcile, "_healthy_existing_owner",
        lambda policy, interface, runner: {"interface": "wlan0", "connection": "home", "actual": policy["address"]},
    )
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("must not duplicate IP"))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "healthy"
    assert written[-1]["interface"] == "wlan0"


def test_multiple_local_owners_fail_closed(monkeypatch):
    _base(monkeypatch)
    monkeypatch.setattr(reconcile, "_target_owners", lambda target, runner: ["eth0", "wlan0"])
    monkeypatch.setattr(reconcile, "apply_static_ip", lambda *a, **k: pytest.fail("must not change network"))
    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))
    assert result["status"] == "repair_failed"
    assert "multiple local interfaces" in result["error"]


def test_trusted_path_rejects_gateway_fingerprint_mismatch(monkeypatch):
    monkeypatch.setattr(
        reconcile,
        "_default_route",
        lambda runner: {"gateway": "10.77.0.254", "interface": "wlan0"},
    )
    monkeypatch.setattr(
        reconcile, "_interface_ipv4", lambda interface, runner: ("10.77.0.88", 24)
    )
    monkeypatch.setattr(
        reconcile, "_gateway_mac", lambda interface, gateway, runner: "00:11:22:33:44:55"
    )
    with pytest.raises(reconcile.NetworkReconcileError, match="fingerprint"):
        reconcile._trusted_active_path(_policy(), runner=lambda *a, **k: None)


def test_legacy_policy_migration_requires_static_profile_anchor(monkeypatch):
    monkeypatch.setattr(reconcile, "_role", lambda: "master")
    monkeypatch.setattr(
        reconcile, "_target_from_root_state", lambda role, runner: "10.77.0.200"
    )
    monkeypatch.setattr(
        reconcile,
        "_default_route",
        lambda runner: {"gateway": "10.77.0.254", "interface": "wlan0"},
    )
    monkeypatch.setattr(
        reconcile, "_interface_ipv4", lambda interface, runner: ("10.77.0.88", 24)
    )
    monkeypatch.setattr(reconcile, "_manual_profile_anchor", lambda target, runner: None)
    monkeypatch.setattr(reconcile, "read_expected_network", lambda: None)
    with pytest.raises(reconcile.NetworkReconcileError, match="static profile anchors"):
        reconcile._migrate_policy(runner=lambda *a, **k: None)



def test_policy_migration_prefers_root_owned_expected_network_over_saved_wifi_profiles(monkeypatch):
    monkeypatch.setattr(reconcile, "_role", lambda: "master")
    monkeypatch.setattr(
        reconcile, "_target_from_root_state", lambda role, runner: "10.77.0.200"
    )
    monkeypatch.setattr(
        reconcile, "_default_route",
        lambda runner: {"gateway": "10.77.0.254", "interface": "wlan0"},
    )
    monkeypatch.setattr(
        reconcile, "_interface_ipv4", lambda interface, runner: ("10.77.0.200", 24)
    )
    monkeypatch.setattr(
        reconcile, "read_expected_network",
        lambda: {
            "address": "10.77.0.200",
            "prefix": 24,
            "gateway": "10.77.0.254",
            "dns": ["10.77.0.254", "203.0.113.53"],
        },
    )
    monkeypatch.setattr(
        reconcile, "_manual_profile_anchor",
        lambda target, runner: pytest.fail(
            "inactive saved Wi-Fi profiles must not override root-owned expected policy"
        ),
    )
    monkeypatch.setattr(
        reconcile, "_gateway_mac", lambda interface, gateway, runner: "aa:bb:cc:dd:ee:ff"
    )
    monkeypatch.setattr(reconcile, "_connection_name", lambda interface, runner: "TELUS5386-5G")
    monkeypatch.setattr(
        reconcile, "_connection_values",
        lambda connection, runner: {
            "uuid": "abc", "type": "802-11-wireless", "method": "manual",
            "addresses": "10.77.0.200/24", "gateway": "10.77.0.254",
            "dns": ["10.77.0.254", "203.0.113.53"],
        },
    )
    monkeypatch.setattr(reconcile, "load_node_identity", lambda: None)
    written = []
    monkeypatch.setattr(
        reconcile, "_atomic_json",
        lambda path, payload, mode=0o600: written.append((path, dict(payload))),
    )
    monkeypatch.setattr(reconcile, "write_expected_network", lambda payload: None)

    policy = reconcile._migrate_policy(runner=lambda *a, **k: None)

    assert policy["address"] == "10.77.0.200"
    assert policy["dns"] == ["10.77.0.254", "203.0.113.53"]
    assert written and written[0][0] == reconcile.POLICY_PATH

def test_status_write_keeps_private_state_and_publishes_sanitized_health(monkeypatch):
    import grp

    calls = []

    def fake_getgrnam(name):
        assert name == "lattice"
        return type("Group", (), {"gr_gid": 4242})()

    monkeypatch.setattr(grp, "getgrnam", fake_getgrnam)

    monkeypatch.setattr(
        reconcile,
        "_atomic_json",
        lambda path, payload, mode=0o644, gid=None: calls.append((path, dict(payload), mode, gid)),
    )
    result = reconcile._write_status(
        "drift_pending",
        expected="10.77.0.200",
        actual="10.77.0.88",
        interface="wlan0",
        first_seen="private-value",
        last_repair_at="private-value",
        retry_after_seconds=42,
    )
    assert result["status"] == "drift_pending"
    assert calls[0][0] == reconcile.PRIVATE_STATUS_PATH
    assert calls[0][2] == 0o600
    assert calls[1][0] == reconcile.HEALTH_STATUS_PATH
    assert calls[1][2] == 0o640
    assert calls[1][3] == 4242
    public = calls[1][1]
    assert public["expected"] == "10.77.0.200"
    assert public["retry_after_seconds"] == 42
    assert "first_seen" not in public
    assert "last_repair_at" not in public


def test_read_network_health_uses_runtime_health_file(monkeypatch):
    seen = []
    monkeypatch.setattr(
        reconcile,
        "_safe_root_json",
        lambda path: seen.append(path) or {
            "status": "healthy",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "expected": "10.77.0.201",
            "actual": "10.77.0.201",
            "interface": "wlo1",
        },
    )
    health = reconcile.read_network_health()
    assert seen == [reconcile.HEALTH_STATUS_PATH]
    assert health["status"] == "healthy"
    assert health["expected"] == "10.77.0.201"


def test_fresh_worker_without_master_assignment_cannot_create_network_policy(monkeypatch):
    monkeypatch.setattr(reconcile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reconcile, "_role", lambda: "worker")
    monkeypatch.setattr(reconcile, "_load_policy", lambda: None)
    monkeypatch.setattr(reconcile, "_safe_root_json", lambda path: None)
    monkeypatch.setattr(
        reconcile, "_migrate_policy",
        lambda runner: pytest.fail("fresh Worker must not migrate temporary IP"),
    )
    written = []
    monkeypatch.setattr(
        reconcile, "_write_status",
        lambda state, **fields: written.append({"status": state, **fields}) or written[-1],
    )

    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))

    assert result == {"status": "awaiting_assignment"}


def test_worker_can_build_policy_only_after_root_owned_assignment_completed(monkeypatch):
    monkeypatch.setattr(reconcile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reconcile, "_role", lambda: "worker")
    monkeypatch.setattr(reconcile, "_load_policy", lambda: None)
    monkeypatch.setattr(
        reconcile, "_safe_root_json",
        lambda path: {"status": "complete", "address": "10.77.0.202"},
    )
    policy = {**_policy(), "role": "worker", "address": "10.77.0.202"}
    monkeypatch.setattr(reconcile, "_migrate_policy", lambda runner: policy)
    monkeypatch.setattr(reconcile, "_target_owners", lambda target, runner: ["wlan0"] )
    monkeypatch.setattr(
        reconcile, "_healthy_existing_owner",
        lambda policy, interface, runner: {
            "interface": interface, "connection": "home", "actual": policy["address"]
        },
    )
    written = []
    monkeypatch.setattr(
        reconcile, "_write_status",
        lambda state, **fields: written.append({"status": state, **fields}) or written[-1],
    )

    result = reconcile.reconcile_once(now=datetime.now(timezone.utc))

    assert result["status"] == "healthy"
    assert result["expected"] == "10.77.0.202"


def test_failed_repair_sets_attempt_timestamp_for_cooldown(monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    now = datetime.now(timezone.utc)
    written = _base(
        monkeypatch,
        {"status": "drift_pending", "expected": "10.77.0.200",
         "actual": "10.77.0.88", "interface": "wlan0", "first_seen": old.isoformat()},
    )
    monkeypatch.setattr(reconcile, "is_address_available", lambda *a, **k: False)
    result = reconcile.reconcile_once(now=now)
    assert result["status"] == "repair_failed"
    assert result["last_attempt_at"] == now.isoformat()


def test_stale_network_health_is_not_reported_healthy(monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    monkeypatch.setattr(
        reconcile, "_safe_root_json",
        lambda path: {"status": "healthy", "updated_at": old.isoformat(), "expected": "x", "actual": "x"},
    )
    health = reconcile.read_network_health()
    assert health["status"] == "unhealthy"
    assert health["stale"] is True
