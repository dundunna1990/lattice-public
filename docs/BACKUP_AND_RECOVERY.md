# Backup and Recovery

## Backup Model

Lattice uses Restic and a source-owned backup design. The source computer reads its own data and writes directly to the assigned target node over the dedicated Backup SFTP transport on port 22024.

The Master coordinates assignments and receives observations but does not carry backup payload data.

## Safety

Backup excludes Lattice-managed peer mounts and other paths that would cause recursion or meaningless duplication. A target is identified by filesystem UUID rather than a transient mount path.

## Retention and Verification

Default retention is 30 daily, 26 weekly, and 12 monthly snapshots. Maintenance performs retention work and periodic repository verification.

## Restore

Restore is staged first, then placed into the requested destination. Lattice does not restore Restic data directly into a live Home directory.

## Recovery Kit

`lattice backup-recovery` supports exporting, inspecting, and extracting an encrypted source-independent recovery kit.

Use:

```bash
lattice backup-recovery --help
```

Store recovery-kit material separately from the computer it protects and protect its passphrase like any other recovery credential.
