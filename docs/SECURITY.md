# Security

Lattice is designed for a small trusted LAN, but it still separates identities, transports, privileges, and operator access.

## Operator Boundary

Human operators use a read-only operator interface separate from the privileged Master socket. Membership in `lattice-operator` does not grant arbitrary database, token, filesystem, or root access.

Privileged helpers are root-owned and expose narrow fixed operations through sudoers rules.

## Transport Separation

Administrative SSH, file access, trusted shell, and Backup SFTP use separate channels and identities. Backup keys are distinct from other transport keys.

## Identity

Fleet membership is signed. Permanent node IDs identify nodes; IP addresses are only current routes.

## Runtime Hardening

Systemd units use sandboxing and privilege-reduction settings where compatible, including `NoNewPrivileges` and protected kernel/control-group settings for sensitive oneshot services.

## Operational Guidance

Keep host keys and recovery credentials protected, use ordinary port-22 SSH for software upgrades, and do not bypass host-key verification when a node changes address. Verify the node's key before accepting a new address.
