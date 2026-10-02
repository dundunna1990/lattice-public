import pytest

from lattice.core import self_check


def test_all_green_resolves_legacy(monkeypatch):
    calls = []
    monkeypatch.setattr(self_check, "check_db", lambda: None)
    monkeypatch.setattr(self_check, "check_socket", lambda: None)
    monkeypatch.setattr(self_check, "audit_log_capacity", lambda: (0, None))
    import lattice.core.events as events
    monkeypatch.setattr(events, "sync_master_self_check_alert", lambda name, error, **kwargs: calls.append((name, error, kwargs.get("severity"))))
    monkeypatch.setattr(events, "resolve_legacy_master_self_check_alerts", lambda: calls.append(("legacy", None)) or 3)
    self_check.main()
    assert calls == [("db", None, None), ("socket", None, None), ("audit_log", None, None), ("legacy", None)]


def test_partial_failure_does_not_resolve_legacy(monkeypatch):
    calls = []
    monkeypatch.setattr(self_check, "check_db", lambda: None)
    monkeypatch.setattr(self_check, "check_socket", lambda: (_ for _ in ()).throw(OSError("refused")))
    monkeypatch.setattr(self_check, "audit_log_capacity", lambda: (0, None))
    import lattice.core.events as events
    monkeypatch.setattr(events, "sync_master_self_check_alert", lambda name, error, **kwargs: calls.append((name, error, kwargs.get("severity"))))
    monkeypatch.setattr(events, "resolve_legacy_master_self_check_alerts", lambda: pytest.fail("must not clear legacy while any check fails"))
    with pytest.raises(SystemExit):
        self_check.main()
    assert calls[0] == ("db", None, None)
    assert calls[1][0] == "socket" and "refused" in calls[1][1]
