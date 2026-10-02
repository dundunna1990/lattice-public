# Operator Guide

## TUI

Run:

```bash
lattice re-run
```

The TUI is role-aware. A Master shows fleet-wide status and controls; a Worker shows local status and local actions.

## Core CLI Commands

```text
lattice status
lattice workers list
lattice mounts fleet
lattice shell status
lattice alerts list
lattice events
lattice services list
lattice system status
lattice autoheal status
```

Master-only fleet commands fail closed on a Worker.

## File Access

Peer Home directories are intentionally mounted read/write. Treat them as real remote file access, not a backup substitute.

## Alerts

Use `lattice alerts list` and `lattice alerts get <id>` to inspect incidents. Alerts resolve from current evidence rather than by deleting history.

## Local Maintenance

Daily Care can be run manually from the local TUI or through the narrow local Care helper. Scheduled Care runs are local to each node; the Master does not remotely clean Workers.
