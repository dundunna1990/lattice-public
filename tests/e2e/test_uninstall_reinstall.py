"""Full Worker uninstall/network-restore/reinstall/re-pair lifecycle."""
from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import time

import pytest

from .conftest import WORKER_HOST, WORKER_USER, ssh as base_ssh
from .test_pairing_reset import (
    _pair_process,
    _wait_healthy,
    _wait_mount_and_shell,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.destructive_e2e,
    pytest.mark.fleet_reset_e2e,
]

WORKER_MDNS = f"{WORKER_HOST}.local"
WORKER_REPO = os.environ.get(
    "LATTICE_E2E_WORKER_REPO",
    "/tmp/lattice-e2e-worker-current",
)

WORKER_IDENTITY = os.environ.get(
    "LATTICE_E2E_WORKER_IDENTITY",
    "/tmp/lattice-e2e-worker-id",
)
TEMP_KEY_MARKER = "lattice-e2e-temp-worker"

SYSTEM_RECOVERY_CONF = (
    "/etc/ssh/sshd_config.d/99-lattice-e2e-recovery.conf"
)
SYSTEM_RECOVERY_KEY_DIR = (
    "/etc/ssh/lattice-e2e-authorized-keys"
)
SYSTEM_RECOVERY_KEY = (
    f"{SYSTEM_RECOVERY_KEY_DIR}/{WORKER_USER}"
)

E2E_LIFECYCLE_SUDOERS = (
    "/etc/sudoers.d/lattice-e2e-lifecycle"
)
E2E_OFFER_HELPER = (
    "/tmp/lattice-e2e-prepare-offer.py"
)


def _ok(result, label: str) -> str:
    assert result.returncode == 0, (
        f"{label}\n"
        f"stdout={result.stdout}\n"
        f"stderr={result.stderr}"
    )
    return result.stdout.strip()


def _worker_ssh(
    host: str,
    command: str,
    *,
    timeout: int = 10,
    user: str | None = None,
):
    if host != WORKER_MDNS:
        raise RuntimeError(
            f"Lifecycle Worker SSH must target {WORKER_MDNS}, got {host}"
        )

    if not os.path.isfile(WORKER_IDENTITY):
        pytest.fail(
            f"Temporary E2E identity is missing: {WORKER_IDENTITY}"
        )

    return base_ssh(
        host,
        command,
        timeout=timeout,
        user=user,
        identity_file=WORKER_IDENTITY,
    )


def _remove_temp_identity() -> None:
    result = _worker_ssh(
        WORKER_MDNS,
        (
            "if [ -f ~/.ssh/authorized_keys ]; then "
            f"sed -i '/{TEMP_KEY_MARKER}/d' ~/.ssh/authorized_keys; "
            "fi"
        ),
        timeout=20,
        user=WORKER_USER,
    )
    _ok(result, "remove temporary E2E SSH authorization")

    for path in (
        WORKER_IDENTITY,
        WORKER_IDENTITY + ".pub",
    ):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _remove_current_worker() -> None:
    removed = subprocess.run(
        [
            "sudo",
            "-n",
            "env",
            "LATTICE_DB_PATH=/var/lib/lattice/state.sqlite",
            "/opt/lattice/venv/bin/lattice",
            "workers",
            "remove",
            WORKER_HOST,
        ],
        input="y\n",
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if removed.returncode == 0:
        return

    detail = (
        removed.stderr
        or removed.stdout
        or ""
    ).strip()

    # A previous interrupted lifecycle attempt may already have
    # completed the secure Master-side removal. Make retries safe
    # without masking any other removal failure.
    if "not found" in detail.lower():
        return

    pytest.fail(
        "Could not retire existing Worker record\n"
        f"{detail}"
    )


def _wait_worker_ssh(timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    last = ""

    while time.monotonic() < deadline:
        result = _worker_ssh(
            WORKER_MDNS,
            "true",
            timeout=10,
            user=WORKER_USER,
        )
        if result.returncode == 0:
            return

        last = result.stderr or result.stdout
        time.sleep(3)

    pytest.fail(
        "Worker did not return over mDNS/SSH "
        f"after network restore: {last}"
    )


def _launch_lifecycle_root_job() -> None:
    unit = f"e2e-worker-lifecycle-{int(time.time())}"
    uninstall = "/opt/lattice/deploy/uninstall.sh"

    bootstrap_code = r"""
from pathlib import Path
import grp
import os
import secrets

from lattice.core.config import (
    DaemonConfig,
    LatticeConfig,
    MasterConfig,
    WireFormatConfig,
    save_config,
)
from lattice.core.ssh_setup import prepare_local_ssh
from lattice.core.ssh_firewall import (
    ensure_local_lan_ssh_firewall,
)
from lattice.wizard.lifecycle import activate_role

wire = WireFormatConfig()

prepare_local_ssh()
ensure_local_lan_ssh_firewall(
    api_port=wire.port,
)

config = LatticeConfig(
    master=MasterConfig(
        ip="127.0.0.1",
        api_port=8080,
        api_token=secrets.token_hex(32),
        master_key=secrets.token_hex(16),
    ),
    daemon=DaemonConfig(),
    wire_format=wire,
)

path = Path("/etc/lattice/lattice.toml")
save_config(config, str(path))
os.chown(
    path,
    0,
    grp.getgrnam("lattice").gr_gid,
)
os.chmod(path, 0o640)

activate_role("worker")
print("WORKER_READY")
"""

    offer_helper_code = f"""
import json
import socket

from lattice.onboarding import prepare_worker_pairing

offer = prepare_worker_pairing(
    socket.gethostname(),
    {WORKER_USER!r},
)

print(json.dumps({{
    "pairing_id": offer.pairing_id,
    "hostname": offer.hostname,
    "ssh_user": offer.ssh_user,
    "code": offer.code,
}}))
"""

    sudo_rules = "\n".join([
        (
            f"{WORKER_USER} ALL=(root) NOPASSWD: "
            "/usr/bin/cat /etc/lattice/role"
        ),
        (
            f"{WORKER_USER} ALL=(root) NOPASSWD: "
            "/opt/lattice/venv/bin/python "
            f"{E2E_OFFER_HELPER}"
        ),
        (
            f"{WORKER_USER} ALL=(root) NOPASSWD: "
            "/opt/lattice/venv/bin/lattice pairing status"
        ),
        (
            f"{WORKER_USER} ALL=(root) NOPASSWD: "
            "/opt/lattice/venv/bin/lattice pairing approve"
        ),
    ]) + "\n"

    preflight = _worker_ssh(
        WORKER_MDNS,
        (
            f"test -r {shlex.quote(uninstall)} "
            f"&& grep -q -- '--restore-network' "
            f"{shlex.quote(uninstall)} "
            f"&& test -r "
            f"{shlex.quote(WORKER_REPO + '/deploy/install.sh')} "
            f"&& test -r {shlex.quote(SYSTEM_RECOVERY_CONF)} "
            f"&& test -r {shlex.quote(SYSTEM_RECOVERY_KEY)}"
        ),
        timeout=20,
        user=WORKER_USER,
    )
    _ok(
        preflight,
        "verify lifecycle root-job prerequisites",
    )

    payload = "\n".join([
        "set -u",
        (
            f"rm -f "
            f"{shlex.quote(E2E_LIFECYCLE_SUDOERS)} "
            f"{shlex.quote(E2E_OFFER_HELPER)}"
        ),
        (
            "rm -f "
            "/tmp/lattice-e2e-purge.rc "
            "/tmp/lattice-e2e-purge.log "
            "/tmp/lattice-e2e-post-purge.env "
            "/tmp/lattice-e2e-reinstall.rc "
            "/tmp/lattice-e2e-reinstall.log "
            "/tmp/lattice-e2e-bootstrap.rc "
            "/tmp/lattice-e2e-bootstrap.log "
            "/tmp/lattice-e2e-cleanup.ok "
            "/tmp/lattice-e2e-cleanup.rc"
        ),
        (
            f"/bin/bash {shlex.quote(uninstall)} "
            "--purge --restore-network "
            "> /tmp/lattice-e2e-purge.log 2>&1"
        ),
        "purge_rc=$?",
        (
            "printf '%s\\n' \"$purge_rc\" "
            "> /tmp/lattice-e2e-purge.rc"
        ),
        (
            "if [ \"$purge_rc\" -ne 0 ]; then "
            "printf '%s\\n' \"$purge_rc\" "
            "> /tmp/lattice-e2e-bootstrap.rc; "
            "exit \"$purge_rc\"; fi"
        ),
        "state=gone",
        (
            "for path in "
            "/opt/lattice /etc/lattice "
            "/var/lib/lattice /var/lib/lattice-root; do "
            "if [ -e \"$path\" ]; then "
            "state=residue; break; fi; done"
        ),
        (
            "iface=\"$(ip -4 route show default "
            "| awk 'NR==1 {print $5}')\""
        ),
        (
            "conn=\"$(nmcli -g GENERAL.CONNECTION "
            "device show \"$iface\" | head -n1)\""
        ),
        (
            "method=\"$(nmcli -g ipv4.method "
            "connection show \"$conn\")\""
        ),
        (
            "{ "
            "printf 'LATTICE_STATE=%s\\n' \"$state\"; "
            "printf 'IFACE=%s\\n' \"$iface\"; "
            "printf 'CONNECTION=%s\\n' \"$conn\"; "
            "printf 'METHOD=%s\\n' \"$method\"; "
            "} > /tmp/lattice-e2e-post-purge.env"
        ),
        (
            "if [ \"$state\" != gone ] "
            "|| [ \"$method\" != auto ]; then "
            "printf '90\\n' "
            "> /tmp/lattice-e2e-bootstrap.rc; "
            "exit 90; fi"
        ),
        (
            f"cd {shlex.quote(WORKER_REPO)} "
            "&& /bin/bash ./deploy/install.sh "
            "> /tmp/lattice-e2e-reinstall.log 2>&1"
        ),
        "install_rc=$?",
        (
            "printf '%s\\n' \"$install_rc\" "
            "> /tmp/lattice-e2e-reinstall.rc"
        ),
        (
            "if [ \"$install_rc\" -ne 0 ]; then "
            "printf '%s\\n' \"$install_rc\" "
            "> /tmp/lattice-e2e-bootstrap.rc; "
            "exit \"$install_rc\"; fi"
        ),
        (
            f"env SUDO_USER={shlex.quote(WORKER_USER)} "
            "/opt/lattice/venv/bin/python -c "
            f"{shlex.quote(bootstrap_code)} "
            "> /tmp/lattice-e2e-bootstrap.log 2>&1"
        ),
        "bootstrap_rc=$?",
        (
            "printf '%s\\n' \"$bootstrap_rc\" "
            "> /tmp/lattice-e2e-bootstrap.rc"
        ),
        (
            "if [ \"$bootstrap_rc\" -ne 0 ]; then "
            "exit \"$bootstrap_rc\"; fi"
        ),

        (
            f"printf '%s' "
            f"{shlex.quote(offer_helper_code)} "
            f"> {shlex.quote(E2E_OFFER_HELPER)}"
        ),
        (
            f"chown root:root "
            f"{shlex.quote(E2E_OFFER_HELPER)} "
            f"&& chmod 0644 "
            f"{shlex.quote(E2E_OFFER_HELPER)}"
        ),
        (
            f"printf '%s' "
            f"{shlex.quote(sudo_rules)} "
            f"> {shlex.quote(E2E_LIFECYCLE_SUDOERS)}"
        ),
        (
            f"chown root:root "
            f"{shlex.quote(E2E_LIFECYCLE_SUDOERS)} "
            f"&& chmod 0440 "
            f"{shlex.quote(E2E_LIFECYCLE_SUDOERS)}"
        ),
        (
            f"if ! /usr/sbin/visudo -c -f "
            f"{shlex.quote(E2E_LIFECYCLE_SUDOERS)}; then "
            "printf '91\\n' "
            "> /tmp/lattice-e2e-bootstrap.rc; "
            "exit 91; fi"
        ),

        # Keep root authority alive only for final recovery-key cleanup.
        "i=0",
        (
            "while [ ! -f /tmp/lattice-e2e-cleanup.ok ] "
            "&& [ \"$i\" -lt 600 ]; do "
            "sleep 2; i=$((i + 1)); done"
        ),
        (
            "if [ ! -f /tmp/lattice-e2e-cleanup.ok ]; then "
            "printf '124\\n' "
            "> /tmp/lattice-e2e-cleanup.rc; "
            "exit 124; fi"
        ),

        (
            f"rm -f "
            f"{shlex.quote(E2E_LIFECYCLE_SUDOERS)} "
            f"{shlex.quote(E2E_OFFER_HELPER)}"
        ),

        f"conf={shlex.quote(SYSTEM_RECOVERY_CONF)}",
        f"key={shlex.quote(SYSTEM_RECOVERY_KEY)}",
        f"keydir={shlex.quote(SYSTEM_RECOVERY_KEY_DIR)}",
        "off=\"${conf}.off\"",

        # Disable the drop-in first. Keep the key until reload succeeds.
        (
            "if [ -f \"$conf\" ]; then "
            "mv \"$conf\" \"$off\"; fi"
        ),
        (
            "if ! /usr/sbin/sshd -t; then "
            "if [ -f \"$off\" ]; then mv \"$off\" \"$conf\"; fi; "
            "printf '1\\n' > /tmp/lattice-e2e-cleanup.rc; "
            "exit 1; fi"
        ),
        (
            "if ! systemctl reload ssh.service; then "
            "if [ -f \"$off\" ]; then mv \"$off\" \"$conf\"; fi; "
            "/usr/sbin/sshd -t || true; "
            "systemctl reload ssh.service || true; "
            "printf '1\\n' > /tmp/lattice-e2e-cleanup.rc; "
            "exit 1; fi"
        ),
        "rm -f \"$off\" \"$key\"",
        "rmdir \"$keydir\" 2>/dev/null || true",
        "printf '0\\n' > /tmp/lattice-e2e-cleanup.rc",
    ])

    command = (
        "sudo -n systemd-run "
        "--collect "
        f"--unit={shlex.quote(unit)} "
        "/bin/sh -c "
        f"{shlex.quote(payload)}"
    )

    launched = _worker_ssh(
        WORKER_MDNS,
        command,
        timeout=30,
        user=WORKER_USER,
    )
    _ok(
        launched,
        "launch detached purge/reinstall lifecycle",
    )


def _wait_bootstrap_complete(timeout: int = 360) -> None:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        result = _worker_ssh(
            WORKER_MDNS,
            (
                "test -f /tmp/lattice-e2e-bootstrap.rc "
                "&& cat /tmp/lattice-e2e-bootstrap.rc"
            ),
            timeout=10,
            user=WORKER_USER,
        )

        if result.returncode == 0:
            rc = result.stdout.strip()

            if rc == "0":
                return

            details = _worker_ssh(
                WORKER_MDNS,
                (
                    "echo '=== PURGE ==='; "
                    "cat /tmp/lattice-e2e-purge.log "
                    "2>/dev/null || true; "
                    "echo '=== POST PURGE ==='; "
                    "cat /tmp/lattice-e2e-post-purge.env "
                    "2>/dev/null || true; "
                    "echo '=== REINSTALL ==='; "
                    "cat /tmp/lattice-e2e-reinstall.log "
                    "2>/dev/null || true; "
                    "echo '=== BOOTSTRAP ==='; "
                    "cat /tmp/lattice-e2e-bootstrap.log "
                    "2>/dev/null || true"
                ),
                timeout=20,
                user=WORKER_USER,
            )

            pytest.fail(
                "Worker root lifecycle bootstrap failed "
                f"with rc={rc}\n"
                f"{details.stdout}\n"
                f"{details.stderr}"
            )

        time.sleep(3)

    pytest.fail(
        "Worker root lifecycle bootstrap "
        "did not report completion"
    )


def _verify_post_purge_evidence() -> None:
    result = _worker_ssh(
        WORKER_MDNS,
        "cat /tmp/lattice-e2e-post-purge.env",
        timeout=20,
        user=WORKER_USER,
    )
    output = _ok(
        result,
        "read recorded post-purge evidence",
    )

    assert "LATTICE_STATE=gone" in output, output
    assert "METHOD=auto" in output, output


def _finalize_recovery_channel(timeout: int = 120) -> None:
    command = (
        "if [ -f ~/.ssh/authorized_keys ]; then "
        f"sed -i '/{TEMP_KEY_MARKER}/d' "
        "~/.ssh/authorized_keys; "
        "fi; "
        "touch /tmp/lattice-e2e-cleanup.ok; "
        f"i=0; while [ \"$i\" -lt {timeout} ]; do "
        "if [ -f /tmp/lattice-e2e-cleanup.rc ]; then "
        "cat /tmp/lattice-e2e-cleanup.rc; "
        "break; "
        "fi; "
        "sleep 1; i=$((i + 1)); "
        "done; "
        "test -f /tmp/lattice-e2e-cleanup.rc"
    )

    result = _worker_ssh(
        WORKER_MDNS,
        command,
        timeout=timeout + 20,
        user=WORKER_USER,
    )
    output = _ok(
        result,
        "remove temporary system recovery SSH path",
    )

    assert output.splitlines()[-1] == "0", output

    for path in (
        WORKER_IDENTITY,
        WORKER_IDENTITY + ".pub",
    ):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _verify_dhcp_restored() -> None:
    command = r'''
iface="$(ip -4 route show default | awk 'NR==1 {print $5}')"
test -n "$iface"
conn="$(nmcli -g GENERAL.CONNECTION device show "$iface" | head -n1)"
test -n "$conn"
printf 'IFACE=%s\n' "$iface"
printf 'CONNECTION=%s\n' "$conn"
printf 'METHOD='
nmcli -g ipv4.method connection show "$conn"
'''

    result = _worker_ssh(
        WORKER_MDNS,
        command,
        timeout=20,
        user=WORKER_USER,
    )
    output = _ok(
        result,
        "verify restored NetworkManager profile",
    )

    assert "METHOD=auto" in output, output


def _install_worker_files() -> None:
    command = (
        f"cd {shlex.quote(WORKER_REPO)} "
        "&& sudo -n ./deploy/install.sh"
    )

    result = _worker_ssh(
        WORKER_MDNS,
        command,
        timeout=240,
        user=WORKER_USER,
    )
    _ok(result, "reinstall Worker files")


def _configure_worker_headless() -> None:
    code = r'''
from pathlib import Path
import grp
import os
import secrets

from lattice.core.config import (
    DaemonConfig,
    LatticeConfig,
    MasterConfig,
    WireFormatConfig,
    save_config,
)
from lattice.core.ssh_setup import prepare_local_ssh
from lattice.core.ssh_firewall import (
    ensure_local_lan_ssh_firewall,
)
from lattice.wizard.lifecycle import activate_role

wire = WireFormatConfig()

prepare_local_ssh()
ensure_local_lan_ssh_firewall(
    api_port=wire.port,
)

config = LatticeConfig(
    master=MasterConfig(
        ip="127.0.0.1",
        api_port=8080,
        api_token=secrets.token_hex(32),
        master_key=secrets.token_hex(16),
    ),
    daemon=DaemonConfig(),
    wire_format=wire,
)

path = Path("/etc/lattice/lattice.toml")
save_config(config, str(path))
os.chown(
    path,
    0,
    grp.getgrnam("lattice").gr_gid,
)
os.chmod(path, 0o640)

activate_role("worker")
print("WORKER_READY")
'''

    command = (
        "sudo -n env "
        f"SUDO_USER={shlex.quote(WORKER_USER)} "
        "/opt/lattice/venv/bin/python -c "
        f"{shlex.quote(code)}"
    )

    result = _worker_ssh(
        WORKER_MDNS,
        command,
        timeout=180,
        user=WORKER_USER,
    )

    output = _ok(
        result,
        "headless Worker role setup",
    )
    assert "WORKER_READY" in output


def _prepare_offer() -> dict:
    result = _worker_ssh(
        WORKER_MDNS,
        (
            "sudo -n "
            "/opt/lattice/venv/bin/python "
            f"{shlex.quote(E2E_OFFER_HELPER)}"
        ),
        timeout=30,
        user=WORKER_USER,
    )

    output = _ok(
        result,
        "prepare fresh Worker pairing offer",
    )

    return json.loads(output.splitlines()[-1])


def _wait_for_approval_request(
    pairing: subprocess.Popen,
    timeout: int = 90,
) -> None:
    deadline = time.monotonic() + timeout
    last = ""

    while time.monotonic() < deadline:
        if pairing.poll() is not None:
            out, err = pairing.communicate()
            pytest.fail(
                "Master pairing exited before local approval\n"
                f"stdout={out}\n"
                f"stderr={err}"
            )

        status = _worker_ssh(
            WORKER_MDNS,
            (
                "sudo -n "
                "/opt/lattice/venv/bin/lattice "
                "pairing status"
            ),
            timeout=10,
            user=WORKER_USER,
        )

        last = status.stdout + status.stderr

        if (
            status.returncode == 0
            and "Pairing status: awaiting_approval"
            in status.stdout
        ):
            return

        time.sleep(2)

    pairing.terminate()
    try:
        pairing.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pairing.kill()
        pairing.wait(timeout=5)

    pytest.fail(
        "Worker never reached awaiting_approval\n"
        f"{last}"
    )


def _resolve_worker_ip() -> str:
    return socket.gethostbyname(WORKER_MDNS)


def test_e2e_uninstall_001_reinstall_001_full_worker_cycle():
    # Retire the existing fleet identity first. A fresh Worker with the
    # same hostname must never overwrite a live fleet identity.
    _remove_current_worker()

    # A root transient job survives the purge itself. It performs:
    # purge -> DHCP verification -> reinstall -> Worker bootstrap.
    # This avoids depending on sudo privileges after purge correctly
    # restores the Worker's pre-Lattice sudo state.
    _launch_lifecycle_root_job()

    # The system-level E2E recovery key lives outside the Worker's
    # encrypted Home and therefore remains usable before PAM/eCryptfs
    # password login.
    _wait_worker_ssh()
    _wait_bootstrap_complete()

    # These facts were captured by the root job after purge and before
    # reinstall began.
    _verify_post_purge_evidence()

    # Reinstall/bootstrap must not itself replace the restored DHCP
    # profile before the new Worker is paired.
    _verify_dhcp_restored()

    role = _worker_ssh(
        WORKER_MDNS,
        (
            "sudo -n /usr/bin/cat /etc/lattice/role "
            "&& systemctl is-active "
            "lattice-worker.service"
        ),
        timeout=20,
        user=WORKER_USER,
    )
    role_output = _ok(
        role,
        "verify Worker role and daemon",
    )
    assert "worker" in role_output
    assert "active" in role_output

    # Pair the freshly installed Worker.
    temporary_ip = _resolve_worker_ip()
    offer = _prepare_offer()

    pairing = _pair_process(
        temporary_ip,
        offer,
        offer["code"],
    )

    _wait_for_approval_request(pairing)

    approved = _worker_ssh(
        WORKER_MDNS,
        (
            "sudo -n "
            "/opt/lattice/venv/bin/lattice "
            "pairing approve"
        ),
        timeout=30,
        user=WORKER_USER,
    )
    _ok(
        approved,
        "local pairing approval",
    )

    out, err = pairing.communicate(timeout=180)
    assert pairing.returncode == 0, (
        "re-pair after reinstall failed\n"
        f"stdout={out}\n"
        f"stderr={err}"
    )

    # Pairing may move the Worker from DHCP back to its managed static
    # address. Wait for every fleet channel to converge.
    _wait_healthy()
    _wait_mount_and_shell()

    # Only after complete success remove both the encrypted-Home copy
    # and the temporary root-owned recovery SSH path.
    _finalize_recovery_channel()
