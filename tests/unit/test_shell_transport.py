import uuid
from pathlib import Path

import pytest

from lattice.file_access.keys import _ensure_keypair
from lattice.file_access.manifest import normalize_manifest
from lattice.shell_access.transport import (
    render_authorized_keys,
    render_known_hosts,
    render_sshd_config,
    ssh_client_options,
)
from lattice.shell_access.reconcile import _render_client_config


def _pair(tmp_path: Path, name: str):
    return _ensure_keypair(tmp_path / name, "id_ed25519", name)


def _fleet(tmp_path: Path):
    nodes=[]
    for index, hostname in enumerate(("master-node", "worker-node")):
        file_client=_pair(tmp_path, f"file-client-{index}")
        file_host=_pair(tmp_path, f"file-host-{index}")
        shell_client=_pair(tmp_path, f"shell-client-{index}")
        shell_host=_pair(tmp_path, f"shell-host-{index}")
        nodes.append({
            "node_id": str(uuid.uuid4()), "hostname": hostname,
            "role": "master" if index == 0 else "worker", "main_user": "masteruser",
            "file_public_key": file_client.public_key_text,
            "file_host_public_key": file_host.public_key_text,
            "file_host_key_fingerprint": file_host.fingerprint, "file_key_generation": 1,
            "shell_public_key": shell_client.public_key_text,
            "shell_host_public_key": shell_host.public_key_text,
            "shell_host_key_fingerprint": shell_host.fingerprint, "shell_key_generation": 1,
        })
    return normalize_manifest({
        "schema_version": 1, "fleet_id": str(uuid.uuid4()), "generation": 2,
        "members": nodes, "revoked": [],
    }), nodes


def test_shell_sshd_is_public_key_only_full_shell():
    config=render_sshd_config(main_user="masteruser")
    assert "Port 22023" in config
    assert "AddressFamily inet" in config
    assert "PasswordAuthentication no" in config
    assert "KbdInteractiveAuthentication no" in config
    assert "PermitRootLogin no" in config
    assert "UsePAM no" in config
    assert "UsePAM yes" not in config
    assert "PermitTTY yes" in config
    assert "AllowTcpForwarding no" in config
    assert "PermitTunnel no" in config
    assert "Subsystem sftp internal-sftp" in config
    assert "ForceCommand" not in config


def test_shell_sshd_restart_kills_all_old_sessions():
    unit = Path("deploy/systemd/lattice-shell-sshd.service").read_text()
    assert "PrivateTmp=yes" in unit
    assert "KillMode=control-group" in unit
    assert "KillMode=mixed" not in unit


def test_shell_authorization_uses_only_signed_shell_key(tmp_path):
    manifest, nodes=_fleet(tmp_path)
    text=render_authorized_keys(manifest, nodes[0]["node_id"])
    assert nodes[1]["shell_public_key"].split()[1] in text
    assert nodes[1]["file_public_key"].split()[1] not in text
    assert 'from="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"' in text
    assert "no-port-forwarding" in text
    assert "no-pty" not in text


def test_shell_known_hosts_pins_node_id_and_shell_host_key(tmp_path):
    manifest, nodes=_fleet(tmp_path)
    text=render_known_hosts(manifest, nodes[0]["node_id"])
    assert f'lattice-node-{nodes[1]["node_id"]}' in text
    assert nodes[1]["shell_host_public_key"].split()[1] in text
    assert nodes[1]["file_host_public_key"].split()[1] not in text


def test_shell_client_is_strict_and_uses_controlmaster(tmp_path):
    peer=str(uuid.uuid4())
    options=ssh_client_options(
        peer_node_id=peer, client_key=tmp_path / "client",
        known_hosts=tmp_path / "known_hosts", control_path=tmp_path / "socket",
    )
    joined=" ".join(map(str, options))
    assert "22023" in joined
    assert "StrictHostKeyChecking=yes" in joined
    assert f"HostKeyAlias=lattice-node-{peer}" in joined
    assert "NumberOfPasswordPrompts=0" in joined
    assert "ControlMaster=auto" in joined
    assert "ControlPersist=yes" in joined


def test_normal_ssh_alias_reuses_background_socket(tmp_path):
    manifest, nodes=_fleet(tmp_path)
    peer=nodes[1]
    plan={"peers":[{
        "node_id": peer["node_id"], "hostname": peer["hostname"],
        "ip": "10.77.0.40", "remote_user": "masteruser", "port": 22022,
    }]}
    config=_render_client_config(manifest, plan, nodes[0]["node_id"], "masteruser", 22023)
    assert "Host worker-node" in config
    assert "HostName 10.77.0.40" in config
    assert "Port 22023" in config
    assert f"HostKeyAlias lattice-node-{peer['node_id']}" in config
    assert f"ControlPath /run/lattice-shell-control/masteruser-{peer['node_id']}.sock" in config



def test_managed_ssh_alias_prefers_last_successful_planned_route(tmp_path):
    manifest, nodes = _fleet(tmp_path)
    peer = nodes[1]
    plan = {"peers": [{
        "node_id": peer["node_id"],
        "hostname": peer["hostname"],
        "ip": "10.77.0.105",
        "remote_user": peer["main_user"],
        "port": 22023,
        "routes": [
            {"ip": "10.77.0.105", "interface": "wlo1", "kind": "wifi", "priority": 20},
            {"ip": "10.77.0.201", "interface": "wlo1", "kind": "wifi", "priority": 20},
        ],
    }]}
    config = _render_client_config(
        manifest, plan, nodes[0]["node_id"], nodes[0]["main_user"], 22023,
        {peer["node_id"]: "10.77.0.201"},
    )
    assert "HostName 10.77.0.201" in config
    assert "HostName 10.77.0.105" not in config


def test_managed_ssh_alias_rejects_unplanned_preferred_route(tmp_path):
    manifest, nodes = _fleet(tmp_path)
    peer = nodes[1]
    plan = {"peers": [{
        "node_id": peer["node_id"], "hostname": peer["hostname"],
        "ip": "10.77.0.105", "remote_user": peer["main_user"], "port": 22023,
    }]}
    config = _render_client_config(
        manifest, plan, nodes[0]["node_id"], nodes[0]["main_user"], 22023,
        {peer["node_id"]: "10.77.0.250"},
    )
    assert "HostName 10.77.0.105" in config
    assert "HostName 10.77.0.250" not in config

def test_manifest_refuses_key_reuse_across_file_and_shell_roles(tmp_path):
    import uuid
    from lattice.file_access.manifest import FleetManifestError, normalize_manifest
    from lattice.file_access.keys import ensure_file_client_identity, ensure_file_host_identity
    from lattice.shell_access.keys import ensure_shell_host_identity

    reused = ensure_file_client_identity(tmp_path / "reused")
    file_host = ensure_file_host_identity(tmp_path / "file-host-reuse")
    shell_host = ensure_shell_host_identity(tmp_path / "shell-host-reuse")
    payload = {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": 1,
        "members": [{
            "node_id": str(uuid.uuid4()),
            "hostname": "worker-node",
            "role": "worker",
            "main_user": "masteruser",
            "file_public_key": reused.public_key_text,
            "file_host_public_key": file_host.public_key_text,
            "file_host_key_fingerprint": file_host.fingerprint,
            "file_key_generation": 1,
            "shell_public_key": reused.public_key_text,
            "shell_host_public_key": shell_host.public_key_text,
            "shell_host_key_fingerprint": shell_host.fingerprint,
            "shell_key_generation": 1,
        }],
        "revoked": [],
    }
    with pytest.raises(FleetManifestError, match="separate"):
        normalize_manifest(payload)


def test_runtime_shell_client_paths_do_not_require_etc_lattice_traversal():
    from pathlib import Path
    from lattice.shell_access import manager
    from lattice.shell_access.reconcile import _render_client_config
    assert manager.CLIENT_RUNTIME_ROOT == Path("/run/lattice-shell-client")
    manifest, nodes = _fleet(Path("/tmp/lattice-shell-runtime-test"))
    peer = nodes[1]
    plan = {"peers": [{
        "node_id": peer["node_id"],
        "hostname": peer["hostname"],
        "ip": "10.77.0.201",
        "remote_user": peer["main_user"],
        "port": 22023,
    }]}
    config = _render_client_config(
        manifest, plan, nodes[0]["node_id"], nodes[0]["main_user"], 22023
    )
    assert "IdentityFile /run/lattice-shell-client/client_ed25519" in config
    assert "UserKnownHostsFile /run/lattice-shell-client/known_hosts" in config


def test_shell_service_runs_precise_session_cleanup_after_stop():
    unit = Path("deploy/systemd/lattice-shell-sshd.service").read_text()
    assert "ExecStopPost=/opt/lattice/venv/bin/python -m lattice.shell_access.session_cleanup" in unit

def test_session_cleanup_kills_only_ss_reported_dedicated_port_pids(monkeypatch):
    from lattice.shell_access import session_cleanup
    calls=[]
    responses=[{101, 202}, {202}]
    monkeypatch.setattr(session_cleanup, "_session_pids", lambda _port: responses.pop(0))
    monkeypatch.setattr(session_cleanup.os, "kill", lambda pid, sig: calls.append((pid, sig)))
    monkeypatch.setattr(session_cleanup.time, "sleep", lambda _seconds: None)
    assert session_cleanup.terminate_dedicated_shell_sessions(22023) == 2
    assert (101, session_cleanup.signal.SIGTERM) in calls
    assert (202, session_cleanup.signal.SIGTERM) in calls
    assert (202, session_cleanup.signal.SIGKILL) in calls
