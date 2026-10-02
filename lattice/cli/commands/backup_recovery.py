"""Operator CLI for independent encrypted Backup recovery kits."""
from __future__ import annotations

import getpass
import json
from pathlib import Path

from lattice.backup.recovery_kit import (
    BackupRecoveryKitError,
    decrypt_recovery_kit,
    export_recovery_kit,
    extract_recovery_kit,
)


def _passphrase(*, confirm: bool) -> str:
    first = getpass.getpass("Recovery kit passphrase: ")
    if confirm:
        second = getpass.getpass("Confirm recovery kit passphrase: ")
        if first != second:
            raise BackupRecoveryKitError("Recovery kit passphrases did not match")
    return first


def cmd_backup_recovery(args) -> int:
    try:
        if args.action == "export":
            output = export_recovery_kit(Path(args.path), _passphrase(confirm=True))
            print(f"Encrypted recovery kit created: {output}")
            print("Store it separately from both this computer and its sole backup target.")
            return 0
        if args.action == "inspect":
            payload = decrypt_recovery_kit(Path(args.path), _passphrase(confirm=False))
            summary = {
                "schema_version": payload["schema_version"],
                "created_at": payload.get("created_at"),
                "source": payload.get("source"),
                "jobs": [
                    {
                        key: value
                        for key, value in job.items()
                        if key != "restic_password"
                    }
                    for job in payload.get("jobs", [])
                ],
            }
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.action == "extract":
            if not args.destination:
                raise BackupRecoveryKitError("Extract requires an absolute destination path")
            workspace = extract_recovery_kit(
                Path(args.path), Path(args.destination), _passphrase(confirm=False)
            )
            print(f"Protected recovery workspace created: {workspace}")
            print(f"Read {workspace / 'RECOVERY.txt'} before restoring data.")
            return 0
    except BackupRecoveryKitError as exc:
        print(f"Recovery kit error: {exc}")
        return 1
    return 1
