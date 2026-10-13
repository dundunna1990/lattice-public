# Lattice Documentation

New to Lattice? Start with the first three guides below.

## Start here

- [Installation](INSTALLATION.md) — install the Master, install Workers, pair them, support headless machines, upgrade, and remove Lattice
- [Operator Guide](OPERATOR_GUIDE.md) — understand nodes, fleet health, file access, trusted shell, backups, Daily Care, Auto-Heal, alerts, and normal day-to-day use
- [Known Limitations](KNOWN_LIMITATIONS.md) — understand what is still rough or not fully qualified in the Public Alpha

## Detailed reference

- [Architecture](ARCHITECTURE.md) — roles, channels, identity, and state ownership
- [Configuration](CONFIGURATION.md) — important settings and defaults
- [Backup and Recovery](BACKUP_AND_RECOVERY.md) — backup model, retention, restore, and recovery kit
- [Daily Care](DAILY_CARE.md) — maintenance policy, safety rules, and scheduling
- [Security](SECURITY.md) — privilege boundaries, keys, transport separation, and safe operation
- [Troubleshooting](TROUBLESHOOTING.md) — practical diagnostics and common failure cases
- [Release Notes v0.1.0](RELEASE_NOTES_v0.1.0.md) — what is included in the initial public release

## Quick mental model

A **node** is simply a computer running Lattice.

One node is the **Master**. The Master is your main fleet view and is where Workers are added and managed.

Every additional node is a **Worker**. Workers report their health to the Master and participate in Lattice's file, trusted-shell, backup, maintenance, and recovery systems.

If you are installing Lattice for the first time, you do not need to read the Architecture document before setup. Follow the [Installation](INSTALLATION.md) guide first.
