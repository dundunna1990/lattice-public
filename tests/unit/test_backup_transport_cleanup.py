import json
from pathlib import Path
from types import SimpleNamespace

from lattice.backup import transport_cleanup


def test_cleanup_prunes_only_stale_managed_transport(tmp_path, monkeypatch):
    desired = tmp_path / "desired.json"
    desired.write_text(
        '{"schema_version":1,"accounts":["lattice-bkp-aaaaaaaaaaaaaaaaaaaa"]}\n'
    )
    desired.chmod(0o600)
    stale = "lattice-bkp-bbbbbbbbbbbbbbbbbbbb"
    current = "lattice-bkp-aaaaaaaaaaaaaaaaaaaa"
    chroots = tmp_path / "chroots"
    keys = tmp_path / "keys"
    for name in (current, stale):
        (chroots / name / "repo").mkdir(parents=True)
        keys.mkdir(parents=True, exist_ok=True)
        (keys / name).write_text("key")
    monkeypatch.setattr(transport_cleanup, "DEFAULT_CHROOT_ROOT", chroots)
    monkeypatch.setattr(transport_cleanup, "DEFAULT_AUTHORIZED_KEYS_DIR", keys)
    monkeypatch.setattr(transport_cleanup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        transport_cleanup,
        "_safe_json",
        lambda path, allowed_uids, maximum: json.loads(Path(path).read_text()),
    )
    monkeypatch.setattr(transport_cleanup, "exact_mount_source", lambda path: None)
    monkeypatch.setattr(
        transport_cleanup.pwd,
        "getpwall",
        lambda: [
            SimpleNamespace(pw_name=current),
            SimpleNamespace(pw_name=stale),
        ],
    )
    monkeypatch.setattr(
        transport_cleanup.pwd,
        "getpwnam",
        lambda name: (
            SimpleNamespace(pw_uid=1200, pw_dir="/", pw_shell="/usr/sbin/nologin")
            if name == stale else (_ for _ in ()).throw(KeyError(name))
        ),
    )
    monkeypatch.setattr(
        transport_cleanup.grp,
        "getgrnam",
        lambda name: (
            SimpleNamespace(gr_mem=[])
            if name == stale else (_ for _ in ()).throw(KeyError(name))
        ),
    )
    calls = []

    def record(command):
        calls.append(command)

    removed = transport_cleanup.cleanup_stale_transport(desired, runner=record)
    assert removed == 1
    assert (chroots / current).exists()
    assert (keys / current).exists()
    assert not (chroots / stale).exists()
    assert not (keys / stale).exists()
    assert ["/usr/sbin/userdel", stale] in calls
    assert ["/usr/sbin/groupdel", stale] in calls
