import json
import uuid

import pytest

from lattice.file_access.identity import (
    ensure_node_identity,
)
from lattice.file_access.keys import (
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import (
    normalize_manifest,
    sign_manifest,
)
from lattice.file_access.sync import (
    FleetSyncError,
    apply_signed_manifest,
)


def _setup(tmp_path, monkeypatch):
    worker_node_path = tmp_path / "worker-node.json"
    worker_file_dir = tmp_path / "worker-file"

    monkeypatch.setenv(
        "LATTICE_NODE_IDENTITY_PATH",
        str(worker_node_path),
    )
    monkeypatch.setenv(
        "LATTICE_FILE_SSH_DIR",
        str(worker_file_dir),
    )
    monkeypatch.setenv(
        "LATTICE_FLEET_BOOTSTRAP_PATH",
        str(tmp_path / "bootstrap.json"),
    )
    monkeypatch.setenv(
        "LATTICE_FLEET_CACHE_PATH",
        str(tmp_path / "manifest-cache.json"),
    )

    worker_identity = ensure_node_identity(
        "masteruser",
        path=worker_node_path,
        main_uid=1000,
        main_gid=1000,
    )

    worker_client = ensure_file_client_identity(
        worker_file_dir
    )
    worker_host = ensure_file_host_identity(
        worker_file_dir
    )

    master_client = ensure_file_client_identity(
        tmp_path / "master-client"
    )
    master_host = ensure_file_host_identity(
        tmp_path / "master-host"
    )
    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )

    fleet_id = str(uuid.uuid4())
    master_node_id = str(uuid.uuid4())

    bootstrap = {
        "fleet_id": fleet_id,
        "master_node_id": master_node_id,
        "master_file_public_key":
            master_client.public_key_text,
        "master_file_host_public_key":
            master_host.public_key_text,
        "master_file_host_key_fingerprint":
            master_host.fingerprint,
        "fleet_signing_public_key":
            signing.public_key_text,
    }

    (tmp_path / "bootstrap.json").write_text(
        json.dumps(bootstrap) + "\n"
    )
    (tmp_path / "bootstrap.json").chmod(0o600)

    manifest = normalize_manifest(
        {
            "schema_version": 1,
            "fleet_id": fleet_id,
            "generation": 2,
            "members": [
                {
                    "node_id": master_node_id,
                    "hostname": "master-node",
                    "role": "master",
                    "main_user": "masteruser",
                    "file_public_key":
                        master_client.public_key_text,
                    "file_host_public_key":
                        master_host.public_key_text,
                    "file_host_key_fingerprint":
                        master_host.fingerprint,
                    "file_key_generation": 1,
                },
                {
                    "node_id": worker_identity.node_id,
                    "hostname": "worker-node",
                    "role": "worker",
                    "main_user": "masteruser",
                    "file_public_key":
                        worker_client.public_key_text,
                    "file_host_public_key":
                        worker_host.public_key_text,
                    "file_host_key_fingerprint":
                        worker_host.fingerprint,
                    "file_key_generation": 1,
                },
            ],
            "revoked": [],
        }
    )

    signature = sign_manifest(
        manifest,
        signing.private_key,
    )

    return {
        "manifest": manifest,
        "signature": signature,
        "worker_node_id": worker_identity.node_id,
        "signing": signing,
    }


def test_worker_accepts_and_caches_signed_generation(
    tmp_path,
    monkeypatch,
):
    setup = _setup(tmp_path, monkeypatch)

    result = apply_signed_manifest(
        setup["manifest"],
        setup["signature"],
    )

    assert result == {
        "status": "applied",
        "generation": 2,
        "node_id": setup["worker_node_id"],
    }

    cache = json.loads(
        (tmp_path / "manifest-cache.json").read_text()
    )

    assert cache["manifest"]["generation"] == 2

    repeated = apply_signed_manifest(
        setup["manifest"],
        setup["signature"],
    )

    assert repeated["status"] == "already_current"


def test_worker_rejects_tampered_signed_generation(
    tmp_path,
    monkeypatch,
):
    setup = _setup(tmp_path, monkeypatch)

    tampered = json.loads(
        json.dumps(setup["manifest"])
    )
    tampered["members"][0]["hostname"] = "attacker"

    with pytest.raises(
        FleetSyncError,
        match="signature is invalid",
    ):
        apply_signed_manifest(
            tampered,
            setup["signature"],
        )


def test_worker_rejects_manifest_that_omits_itself(
    tmp_path,
    monkeypatch,
):
    setup = _setup(tmp_path, monkeypatch)

    manifest = dict(setup["manifest"])

    # Explicitly keep only the master. Manifest members are sorted by
    # immutable node_id, so positional indexing cannot tell us which
    # member is the master or worker.
    manifest["members"] = [
        member
        for member in setup["manifest"]["members"]
        if member["role"] == "master"
    ]

    assert len(manifest["members"]) == 1

    manifest = normalize_manifest(manifest)

    signature = sign_manifest(
        manifest,
        setup["signing"].private_key,
    )

    with pytest.raises(
        FleetSyncError,
        match="does not contain this computer",
    ):
        apply_signed_manifest(
            manifest,
            signature,
        )


def test_worker_rejects_wrong_fleet(
    tmp_path,
    monkeypatch,
):
    setup = _setup(tmp_path, monkeypatch)

    manifest = dict(setup["manifest"])
    manifest["fleet_id"] = str(uuid.uuid4())
    manifest = normalize_manifest(manifest)

    signature = sign_manifest(
        manifest,
        setup["signing"].private_key,
    )

    with pytest.raises(
        FleetSyncError,
        match="different fleet",
    ):
        apply_signed_manifest(
            manifest,
            signature,
        )


def test_cached_generation_reports_zero_then_current(
    tmp_path,
    monkeypatch,
):
    from lattice.file_access.sync import (
        get_cached_fleet_generation,
    )

    setup = _setup(tmp_path, monkeypatch)

    assert get_cached_fleet_generation() == 0

    apply_signed_manifest(
        setup["manifest"],
        setup["signature"],
    )

    assert get_cached_fleet_generation() == 2


def test_root_reader_accepts_lattice_owned_verified_cache(tmp_path, monkeypatch):
    from lattice.file_access import sync

    cache = tmp_path / "manifest.json"
    cache.write_text('{"manifest": {}, "signature": "x"}\n')

    class Pw:
        pw_uid = 4242

    class Stat:
        st_mode = 0o100600
        st_nlink = 1
        st_uid = 4242
        st_size = len(cache.read_bytes())

    real_open = sync.os.open
    real_fstat = sync.os.fstat
    monkeypatch.setattr(sync.pwd, "getpwnam", lambda _name: Pw())
    monkeypatch.setattr(sync.os, "geteuid", lambda: 0)

    descriptor = real_open(cache, sync.os.O_RDONLY)
    monkeypatch.setattr(sync.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(sync.os, "fstat", lambda _fd: Stat())

    payload = sync._safe_read_json(cache, allow_lattice_owner=True)
    assert payload["signature"] == "x"


def test_root_reader_still_rejects_untrusted_cache_owner(tmp_path, monkeypatch):
    from lattice.file_access import sync

    cache = tmp_path / "manifest.json"
    cache.write_text('{}\n')

    class Pw:
        pw_uid = 4242

    class Stat:
        st_mode = 0o100600
        st_nlink = 1
        st_uid = 9999
        st_size = len(cache.read_bytes())

    real_open = sync.os.open
    descriptor = real_open(cache, sync.os.O_RDONLY)
    monkeypatch.setattr(sync.pwd, "getpwnam", lambda _name: Pw())
    monkeypatch.setattr(sync.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sync.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(sync.os, "fstat", lambda _fd: Stat())

    with pytest.raises(sync.FleetSyncError, match="unexpected ownership"):
        sync._safe_read_json(cache, allow_lattice_owner=True)
