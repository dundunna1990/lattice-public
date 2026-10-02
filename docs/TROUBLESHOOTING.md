# Troubleshooting

## Start With Current State

```bash
lattice status
lattice system status
systemctl --failed
```

For fleet details, also inspect:

```bash
lattice workers list
lattice mounts fleet
lattice shell status
lattice alerts list
```

## Worker Appears Down

A sleeping laptop or disconnected Wi-Fi can legitimately stop heartbeats. Confirm the machine is awake before treating the condition as a fault.

## Node IP Changed

Lattice identifies nodes by node ID, not IP. Use the current route reported by Lattice. For administrative SSH at a new address, verify the host key before trusting it.

## Backup Alert After Upgrade

Check that `/opt/lattice/bin/restic` exists and that Backup maintenance succeeds. The alert evaluator resolves an incident from fresh successful evidence.

## Care Reports Critical Disk Usage

Care does not delete Home data. Check `df -h /` and identify large personal files yourself. Free space deliberately, then rerun Care.

## Logs

Use `lattice logs`, `lattice system logs`, or `journalctl -u <unit>` for the relevant service.
