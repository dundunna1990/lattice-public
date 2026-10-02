"""lattice.cli.commands.system — operator commands for the Boot & Resilience Layer."""
import subprocess
import logging

from lattice.wizard.lifecycle import RoleLifecycleError, current_role

logger = logging.getLogger(__name__)


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _resolve_targets(target):
    role = current_role()
    if role is None:
        raise RoleLifecycleError("This machine has no configured Lattice role. Run setup first.")
    if target == "all":
        return [f"lattice-{role}"]
    if target != role:
        raise RoleLifecycleError(
            f"This machine is configured as {role}; refusing to operate the {target} role."
        )
    return [f"lattice-{target}"]


def _status():
    for svc in [
        "lattice-init",
        "lattice-boot-recovery",
        "lattice-master",
        "lattice-worker",
        "lattice-health-watchdog.timer",
        "lattice-backup.timer",
        "lattice-care.timer",
        "lattice-care.service",
        "lattice-backup.service",
        "lattice-backup-run-request.path",
        "lattice-backup-run-request.service",
        "lattice-backup-query.path",
        "lattice-backup-query.service",
        "lattice-backup-restore.path",
        "lattice-backup-restore.service",
        "lattice-backup-maintenance.timer",
        "lattice-backup-maintenance.service",
        "lattice-backup-alerts.timer",
        "lattice-backup-alerts.service",
        "lattice-backup-observation-refresh.timer",
        "lattice-backup-observation-refresh.service",
        "lattice-backup-sshd",
        "lattice-backup-transport-reconcile.path",
        "lattice-backup-assignment-reconcile.timer",
        "lattice-file-sshd",
        "lattice-file-transport-reconcile.path",
        "lattice-mount-manager",
        "lattice-shell-sshd",
        "lattice-shell-connection-manager",
    ]:
        r = _run(["systemctl", "is-active", svc], timeout=5)
        print(f"  {svc:35s} {r.stdout.strip()}")


def _restart(target):
    try:
        targets = _resolve_targets(target)
    except RoleLifecycleError as exc:
        print(f"  ERROR: {exc}")
        return 1

    failed = False
    for t in targets:
        print(f"  restarting {t}...")
        r = _run(["sudo", "-n", "systemctl", "restart", t])
        if r.returncode != 0:
            print(f"  ERROR: {r.stderr.strip()}")
            failed = True
    return 1 if failed else 0


def _stop(target):
    try:
        targets = _resolve_targets(target)
    except RoleLifecycleError as exc:
        print(f"  ERROR: {exc}")
        return 1

    failed = False
    for t in targets:
        print(f"  stopping {t}...")
        r = _run(["sudo", "-n", "systemctl", "stop", t])
        if r.returncode != 0:
            print(f"  ERROR: {r.stderr.strip()}")
            failed = True
    return 1 if failed else 0


def _start(target):
    try:
        targets = _resolve_targets(target)
    except RoleLifecycleError as exc:
        print(f"  ERROR: {exc}")
        return 1

    failed = False
    for t in targets:
        print(f"  starting {t}...")
        r = _run(["sudo", "-n", "systemctl", "start", t])
        if r.returncode != 0:
            print(f"  ERROR: {r.stderr.strip()}")
            failed = True
    return 1 if failed else 0


def _logs(n, follow):
    role = current_role()
    if role is None:
        print("  ERROR: This machine has no configured Lattice role. Run setup first.")
        return
    cmd = ["journalctl", "-u", f"lattice-{role}", "-n", str(n), "--no-pager"]
    if follow:
        cmd.append("-f")
    try:
        subprocess.run(cmd, timeout=None)
    except KeyboardInterrupt:
        pass


def _test_reboot():
    print("Simulating reboot by restarting this machine's one configured Lattice role...")
    _restart("all")
    print("Done. Check 'lattice system status' to confirm.")


def _verify_units():
    units = [
        "lattice-init.service",
        "lattice-boot-recovery.service",
        "lattice-master.service",
        "lattice-worker.service",
        "lattice-health-watchdog.timer",
        "lattice-backup.timer",
        "lattice-care.timer",
        "lattice-care.service",
        "lattice-backup.service",
        "lattice-backup-run-request.path",
        "lattice-backup-run-request.service",
        "lattice-backup-query.path",
        "lattice-backup-query.service",
        "lattice-backup-restore.path",
        "lattice-backup-restore.service",
        "lattice-backup-maintenance.timer",
        "lattice-backup-maintenance.service",
        "lattice-backup-alerts.timer",
        "lattice-backup-alerts.service",
        "lattice-backup-observation-refresh.timer",
        "lattice-backup-observation-refresh.service",
        "lattice-backup-sshd.service",
        "lattice-backup-transport-reconcile.path",
        "lattice-backup-assignment-reconcile.timer",
        "lattice-file-sshd.service",
        "lattice-file-transport-reconcile.path",
        "lattice-mount-manager.service",
        "lattice-shell-sshd.service",
        "lattice-shell-connection-manager.service",
    ]
    print("Lattice systemd units:")
    for u in units:
        r = _run(["systemctl", "is-enabled", u], timeout=5)
        print(f"  {u:40s} {r.stdout.strip()}")


def cmd_system(args):
    logger.info(f"cmd_system: action={args.action}")
    if args.action == "status":
        _status()
        return 0
    elif args.action == "restart":
        return _restart(args.target)
    elif args.action == "stop":
        return _stop(args.target)
    elif args.action == "start":
        return _start(args.target)
    elif args.action == "logs":
        _logs(args.n, args.follow)
    elif args.action == "test-reboot":
        _test_reboot()
    elif args.action == "verify-units":
        _verify_units()
