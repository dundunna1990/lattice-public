from pathlib import Path
import uuid

import pytest

from lattice.file_access.keys import (
    ensure_file_client_identity,
    ensure_file_host_identity,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
)
from lattice.file_access.transport import (
    FileTransportError,
    PRIVATE_LAN_CIDRS,
    host_key_alias,
    render_authorized_keys,
    render_known_hosts,
    render_sshd_config,
    ssh_client_options,
)


def _member(
    tmp_path,
    *,
    name,
    role,
    user,
):
    client = ensure_file_client_identity(
        tmp_path / f"{name}-client"
    )
    host = ensure_file_host_identity(
        tmp_path / f"{name}-host"
    )

    return {
        "node_id": str(uuid.uuid4()),
        "hostname": name,
        "role": role,
        "main_user": user,
        "file_public_key":
            client.public_key_text,
        "file_host_public_key":
            host.public_key_text,
        "file_host_key_fingerprint":
            host.fingerprint,
        "file_key_generation": 1,
    }


def _fleet(tmp_path):
    master = _member(
        tmp_path,
        name="master-node",
        role="master",
        user="masteruser",
    )

    local = _member(
        tmp_path,
        name="worker-node",
        role="worker",
        user="workeruser",
    )

    remote = _member(
        tmp_path,
        name="backup-node",
        role="worker",
        user="backupuser",
    )

    manifest = normalize_manifest(
        {
            "schema_version": 1,
            "fleet_id": str(uuid.uuid4()),
            "generation": 3,
            "members": [
                master,
                local,
                remote,
            ],
            "revoked": [],
        }
    )

    return manifest, master, local, remote


def test_authorized_keys_contains_only_other_active_members(
    tmp_path,
):
    manifest, master, local, remote = _fleet(
        tmp_path
    )

    rendered = render_authorized_keys(
        manifest,
        local["node_id"],
    )

    lines = rendered.splitlines()

    assert len(lines) == 2

    expected_sources = ",".join(
        PRIVATE_LAN_CIDRS
    )

    for line in lines:
        assert line.startswith(
            f'restrict,from="{expected_sources}" '
        )
        assert "ssh-ed25519 " in line

    assert master["node_id"] in rendered
    assert remote["node_id"] in rendered
    assert local["node_id"] not in rendered

    assert "command=" not in rendered
    assert "permitopen=" not in rendered


def test_known_hosts_uses_node_identity_not_ip_or_hostname(
    tmp_path,
):
    manifest, master, local, remote = _fleet(
        tmp_path
    )

    rendered = render_known_hosts(
        manifest,
        local["node_id"],
    )

    assert (
        host_key_alias(master["node_id"])
        in rendered
    )
    assert (
        host_key_alias(remote["node_id"])
        in rendered
    )
    assert (
        host_key_alias(local["node_id"])
        not in rendered
    )

    assert "192.168." not in rendered
    assert "master-node.local" not in rendered


def test_dedicated_sshd_is_sftp_only_and_chrooted():
    config = render_sshd_config(
        main_user="masteruser",
    )

    required = [
        "Port 22022",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin no",
        "AuthenticationMethods publickey",
        "AllowUsers masteruser",
        "DisableForwarding yes",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "PermitTunnel no",
        "PermitTTY no",
        "X11Forwarding no",
        "PermitUserRC no",
        "Subsystem sftp internal-sftp",
        (
            "ChrootDirectory "
            "/srv/lattice-file-root"
        ),
        "ForceCommand internal-sftp -d /Home",
    ]

    for expected in required:
        assert expected in config

    assert "PasswordAuthentication yes" not in config
    assert "PermitRootLogin yes" not in config


def test_sshd_refuses_root_lattice_and_invalid_user():
    for user in (
        "root",
        "lattice",
        "bad user",
        "bad\nuser",
    ):
        with pytest.raises(
            FileTransportError
        ):
            render_sshd_config(
                main_user=user,
            )


def test_ssh_client_requires_exact_host_identity(
    tmp_path,
):
    node_id = str(uuid.uuid4())

    options = ssh_client_options(
        peer_node_id=node_id,
        client_key=Path(
            "/etc/lattice/file-ssh/client_ed25519"
        ),
    )

    joined = " ".join(options)

    assert "BatchMode=yes" in joined
    assert "IdentitiesOnly=yes" in joined
    assert "StrictHostKeyChecking=yes" in joined
    assert (
        f"HostKeyAlias=lattice-node-{node_id}"
        in joined
    )
    assert "GlobalKnownHostsFile=/dev/null" in joined
    assert "ConnectTimeout=5" in joined
    assert "ServerAliveInterval=10" in joined
    assert "ServerAliveCountMax=2" in joined


def test_transport_refuses_relative_security_paths():
    with pytest.raises(
        FileTransportError,
        match="absolute path",
    ):
        render_sshd_config(
            main_user="masteruser",
            host_key=Path("relative/key"),
        )


def test_manifest_rejects_hostname_line_injection(
    tmp_path,
):
    manifest, _, local, _ = _fleet(
        tmp_path
    )

    raw = {
        **manifest,
        "members": [
            dict(member)
            for member in manifest["members"]
        ],
    }

    target = next(
        item
        for item in raw["members"]
        if item["node_id"] != local["node_id"]
    )

    target["hostname"] = (
        'evil\nssh-ed25519 AAAA injected'
    )

    with pytest.raises(
        FleetManifestError,
        match="hostname is invalid",
    ):
        normalize_manifest(raw)


def test_manifest_rejects_duplicate_fleet_hostname(
    tmp_path,
):
    manifest, _, _, _ = _fleet(
        tmp_path
    )

    raw = {
        **manifest,
        "members": [
            dict(member)
            for member in manifest["members"]
        ],
    }

    raw["members"][1]["hostname"] = (
        raw["members"][0]["hostname"].upper()
    )

    with pytest.raises(
        FleetManifestError,
        match="duplicate hostname",
    ):
        normalize_manifest(raw)


def test_manifest_rejects_reused_client_key(
    tmp_path,
):
    manifest, _, _, _ = _fleet(
        tmp_path
    )

    raw = {
        **manifest,
        "members": [
            dict(member)
            for member in manifest["members"]
        ],
    }

    raw["members"][1][
        "file_public_key"
    ] = raw["members"][0][
        "file_public_key"
    ]

    with pytest.raises(
        FleetManifestError,
        match="reuses a file client key",
    ):
        normalize_manifest(raw)


def test_file_sshd_unit_is_not_the_normal_ssh_service():
    unit = Path(
        "deploy/systemd/"
        "lattice-file-sshd.service"
    ).read_text()

    assert (
        "ConditionPathExists="
        "/etc/lattice/file-ssh/sshd_config"
        in unit
    )

    assert (
        "ConditionPathExists="
        "/srv/lattice-file-root/Home"
        in unit
    )

    assert (
        "sshd -t -f "
        "/etc/lattice/file-ssh/sshd_config"
        in unit
    )

    assert (
        "sshd -D -e -f "
        "/etc/lattice/file-ssh/sshd_config"
        in unit
    )
