"""Build a fail-closed local plan from one signed backup assignment document."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lattice.backup.assignment import normalize_assignment, verify_assignment
from lattice.backup.targets import resolve_repository_root
from lattice.backup.transport import BackupTransportAccount, backup_account_name
from lattice.core.db import get_db_connection
from lattice.file_access.keys import validate_ed25519_public_key


class BackupTransportPlanError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlannedBackupRepository:
    source_node_id: str
    target_uuid: str
    repository_id: str
    repository_path: Path
    account: BackupTransportAccount

    @property
    def username(self) -> str:
        return backup_account_name(self.source_node_id, self.target_uuid)


def build_local_transport_plan(
    assignment_payload: object,
    signature: str,
    signing_public_key: str,
    *,
    local_node_id: str,
    local_host_public_key: str,
    target_resolver=resolve_repository_root,
) -> list[PlannedBackupRepository]:
    normalized = normalize_assignment(assignment_payload)
    if not verify_assignment(normalized, signature, signing_public_key):
        raise BackupTransportPlanError("Backup assignment signature is invalid")
    local_host_key = validate_ed25519_public_key(local_host_public_key)
    selected = [
        item for item in normalized["assignments"]
        if item["target_node_id"] == local_node_id
    ]
    if not selected:
        return []

    conn = get_db_connection()
    try:
        plan: list[PlannedBackupRepository] = []
        for item in selected:
            if item["backup_host_public_key"].split()[:2] != local_host_key.split()[:2]:
                raise BackupTransportPlanError(
                    "Signed backup assignment contains the wrong local backup host key"
                )
            row = conn.execute(
                """SELECT target_uuid, filesystem_uuid, repository_root, repository_relative_path, enabled, host_node_id
                   FROM backup_targets
                   WHERE target_uuid=? AND host_node_id=? LIMIT 1""",
                (item["target_uuid"], local_node_id),
            ).fetchone()
            if row is None or not bool(row["enabled"]):
                raise BackupTransportPlanError(
                    "Signed backup assignment references an unavailable local target"
                )
            try:
                repository_root, _mount = target_resolver(
                    str(row["filesystem_uuid"]), str(row["repository_relative_path"])
                )
            except Exception as exc:
                raise BackupTransportPlanError(
                    f"Backup target {row['target_uuid']} failed physical validation: {exc}"
                ) from exc
            repository_path = repository_root / item["source_node_id"]
            try:
                repository_path.relative_to(repository_root)
            except ValueError as exc:
                raise BackupTransportPlanError("Backup repository path escaped its target root") from exc
            plan.append(
                PlannedBackupRepository(
                    source_node_id=item["source_node_id"],
                    target_uuid=item["target_uuid"],
                    repository_id=item["repository_id"],
                    repository_path=repository_path,
                    account=BackupTransportAccount(
                        item["source_node_id"], item["target_uuid"], item["backup_public_key"]
                    ),
                )
            )
        usernames = [item.username for item in plan]
        if len(usernames) != len(set(usernames)):
            raise BackupTransportPlanError("Backup transport account collision detected")
        return sorted(plan, key=lambda value: value.username)
    finally:
        conn.close()
