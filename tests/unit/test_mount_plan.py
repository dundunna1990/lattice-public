import base64
import json
from pathlib import Path
import uuid

import pytest

import lattice.file_access.mount_plan as mount_plan_mod
from lattice.file_access.keys import (
    fingerprint_ed25519_public_key,
)
from lattice.file_access.manifest import (
    normalize_manifest,
)
from lattice.file_access.mount_plan import (
    MountPlanError,
    build_mount_plan,
    normalize_lan_ip,
    validate_mount_plan,
    write_mount_plan,
)


def _key(fill: bytes) -> str:
    wire = (
        b"\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00\x20"
        + fill * 32
    )

    return (
        "ssh-ed25519 "
        + base64.b64encode(
            wire
        ).decode("ascii")
    )


def _member(
    *,
    node_id,
    hostname,
    user,
    role,
    client_fill,
    host_fill,
):
    host_key = _key(
        host_fill
    )

    return {
        "node_id":
            node_id,
        "hostname":
            hostname,
        "role":
            role,
        "main_user":
            user,
        "file_public_key":
            _key(client_fill),
        "file_host_public_key":
            host_key,
        "file_host_key_fingerprint":
            fingerprint_ed25519_public_key(
                host_key
            ),
        "file_key_generation":
            1,
    }


def _manifest():
    master = _member(
        node_id=(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        ),
        hostname="master-node",
        user="masteruser",
        role="master",
        client_fill=b"a",
        host_fill=b"b",
    )

    worker = _member(
        node_id=(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        ),
        hostname="worker-node",
        user="workeruser",
        role="worker",
        client_fill=b"c",
        host_fill=b"d",
    )

    return normalize_manifest(
        {
            "schema_version":
                1,
            "fleet_id":
                str(uuid.uuid4()),
            "generation":
                4,
            "members":
                [
                    master,
                    worker,
                ],
            "revoked":
                [],
        }
    )


def test_build_plan_uses_only_signed_identity_fields():
    manifest = _manifest()

    plan = build_mount_plan(
        manifest,
        {
            manifest["members"][0][
                "node_id"
            ]:
                "10.77.0.88",
            manifest["members"][1][
                "node_id"
            ]:
                "10.77.0.201",
        },
        port=22022,
    )

    assert plan[
        "generation"
    ] == 4

    by_id = {
        peer["node_id"]:
            peer
        for peer in plan[
            "peers"
        ]
    }

    for member in manifest[
        "members"
    ]:
        peer = by_id[
            member["node_id"]
        ]

        assert (
            peer["hostname"]
            == member["hostname"]
        )

        assert (
            peer["remote_user"]
            == member["main_user"]
        )


def test_plan_rejects_node_outside_signed_fleet():
    manifest = _manifest()

    plan = {
        "generation":
            4,
        "peers":
            [
                {
                    "node_id":
                        str(uuid.uuid4()),
                    "hostname":
                        "attacker",
                    "remote_user":
                        "attacker",
                    "ip":
                        "10.77.0.99",
                    "port":
                        22022,
                }
            ],
    }

    with pytest.raises(
        MountPlanError,
        match="outside the signed fleet",
    ):
        validate_mount_plan(
            manifest,
            plan,
        )


def test_plan_rejects_user_substitution():
    manifest = _manifest()

    member = manifest[
        "members"
    ][0]

    plan = {
        "generation":
            4,
        "peers":
            [
                {
                    "node_id":
                        member["node_id"],
                    "hostname":
                        member["hostname"],
                    "remote_user":
                        "root",
                    "ip":
                        "10.77.0.88",
                    "port":
                        22022,
                }
            ],
    }

    with pytest.raises(
        MountPlanError,
        match="user does not match",
    ):
        validate_mount_plan(
            manifest,
            plan,
        )


def test_plan_rejects_hostname_substitution():
    manifest = _manifest()

    member = manifest[
        "members"
    ][0]

    plan = {
        "generation":
            4,
        "peers":
            [
                {
                    "node_id":
                        member["node_id"],
                    "hostname":
                        "fake-host",
                    "remote_user":
                        member["main_user"],
                    "ip":
                        "10.77.0.88",
                    "port":
                        22022,
                }
            ],
    }

    with pytest.raises(
        MountPlanError,
        match="hostname does not match",
    ):
        validate_mount_plan(
            manifest,
            plan,
        )


def test_plan_rejects_public_locator():
    with pytest.raises(
        MountPlanError,
        match="outside the private LAN",
    ):
        normalize_lan_ip(
            "8.8.8.8"
        )


def test_plan_generation_must_match_manifest():
    manifest = _manifest()

    with pytest.raises(
        MountPlanError,
        match="generation does not match",
    ):
        validate_mount_plan(
            manifest,
            {
                "generation":
                    3,
                "peers":
                    [],
            },
        )


def test_mount_plan_write_is_atomic_and_idempotent(
    tmp_path,
):
    manifest = _manifest()

    plan = build_mount_plan(
        manifest,
        {
            manifest[
                "members"
            ][0]["node_id"]:
                "10.77.0.88",
        },
    )

    destination = (
        tmp_path
        / "mount-plans.json"
    )

    assert write_mount_plan(
        manifest,
        plan,
        path=destination,
    )

    assert not write_mount_plan(
        manifest,
        plan,
        path=destination,
    )

    payload = json.loads(
        destination.read_text()
    )

    assert payload == plan


def test_root_created_default_mount_plan_artifacts_are_handed_to_daemon(
    tmp_path, monkeypatch
):
    manifest = _manifest()
    node_id = manifest["members"][0]["node_id"]
    plan = build_mount_plan(manifest, {node_id: "10.77.0.88"})
    destination = tmp_path / "mount-plans.json"
    lock = tmp_path / "mount-plans.lock"
    ownership = []

    monkeypatch.setattr(mount_plan_mod, "DEFAULT_MOUNT_PLAN_PATH", destination)
    monkeypatch.setattr(mount_plan_mod, "DEFAULT_MOUNT_PLAN_LOCK_PATH", lock)
    monkeypatch.setattr(mount_plan_mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mount_plan_mod, "_daemon_account_ids", lambda: (997, 998))
    monkeypatch.setattr(
        mount_plan_mod.os, "fchown",
        lambda descriptor, uid, gid: ownership.append((uid, gid)),
    )

    assert mount_plan_mod.write_mount_plan(manifest, plan)
    assert ownership == [(997, 998), (997, 998)]
    assert lock.stat().st_mode & 0o777 == 0o640
    assert destination.stat().st_mode & 0o777 == 0o600


def test_mount_plan_never_rolls_back_to_older_generation(tmp_path):
    older_manifest = _manifest()
    newer_manifest = normalize_manifest({
        **older_manifest,
        "generation": older_manifest["generation"] + 1,
    })
    node_id = older_manifest["members"][0]["node_id"]
    older_plan = build_mount_plan(
        older_manifest, {node_id: "10.77.0.88"}
    )
    newer_plan = build_mount_plan(
        newer_manifest, {node_id: "10.77.0.88"}
    )
    destination = tmp_path / "mount-plans.json"

    assert write_mount_plan(newer_manifest, newer_plan, path=destination)
    assert not write_mount_plan(older_manifest, older_plan, path=destination)

    payload = json.loads(destination.read_text())
    assert payload["generation"] == newer_manifest["generation"]


def test_mount_plan_refuses_symlink_destination(
    tmp_path,
):
    manifest = _manifest()

    plan = build_mount_plan(
        manifest,
        {
            manifest[
                "members"
            ][0]["node_id"]:
                "10.77.0.88",
        },
    )

    target = (
        tmp_path / "target"
    )
    target.write_text("{}")

    destination = (
        tmp_path
        / "mount-plans.json"
    )
    destination.symlink_to(
        target
    )

    with pytest.raises(
        MountPlanError,
    ):
        write_mount_plan(
            manifest,
            plan,
            path=destination,
        )

    assert target.read_text() == "{}"


def test_build_plan_carries_signed_revocations():
    manifest = _manifest()

    revoked = (
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    )

    manifest = normalize_manifest(
        {
            **manifest,
            "revoked":
                [revoked],
        }
    )

    plan = build_mount_plan(
        manifest,
        {},
    )

    assert plan[
        "retired_node_ids"
    ] == [revoked]


def test_plan_cannot_invent_revocation():
    manifest = _manifest()

    with pytest.raises(
        MountPlanError,
        match="do not match",
    ):
        validate_mount_plan(
            manifest,
            {
                "generation":
                    manifest[
                        "generation"
                    ],
                "peers":
                    [],
                "retired_node_ids":
                    [
                        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                    ],
            },
        )


def test_missing_locator_does_not_mean_revoked():
    manifest = _manifest()

    plan = build_mount_plan(
        manifest,
        {},
    )

    assert plan[
        "peers"
    ] == []

    assert plan[
        "retired_node_ids"
    ] == []


def test_visible_peers_include_member_without_locator():
    manifest = _manifest()

    plan = build_mount_plan(
        manifest,
        {},
    )

    assert plan["peers"] == []

    assert {
        item["node_id"]
        for item in plan[
            "visible_peers"
        ]
    } == {
        member["node_id"]
        for member in manifest[
            "members"
        ]
    }


def test_visible_registry_cannot_invent_computer():
    manifest = _manifest()

    with pytest.raises(
        MountPlanError,
        match="does not match",
    ):
        validate_mount_plan(
            manifest,
            {
                "generation":
                    manifest[
                        "generation"
                    ],
                "peers":
                    [],
                "visible_peers":
                    [
                        {
                            "node_id":
                                str(
                                    uuid.uuid4()
                                ),
                            "hostname":
                                "fake-peer",
                        }
                    ],
                "retired_node_ids":
                    [],
            },
        )
