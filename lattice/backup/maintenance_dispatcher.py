"""Daily source-owned repository maintenance dispatcher."""
from __future__ import annotations

import logging

from lattice.backup.maintenance import BackupMaintenanceError, maintain_job
from lattice.backup.restore_workflow import (
    BackupRestoreWorkflowError,
    cleanup_restore_staging,
)
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

logger = logging.getLogger(__name__)


def eligible_jobs(source_node_id: str) -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bj.id, bj.job_uuid, fn.hostname AS source_hostname,
                      bt.friendly_name AS target_name
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.source_node_id=? AND bj.enabled=1 AND bj.paused=0 AND bt.enabled=1
                 AND EXISTS(
                     SELECT 1 FROM backup_runs br
                     WHERE br.job_id=bj.id AND br.result='successful'
                 )
               ORDER BY bj.id""",
            (source_node_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def dispatch_maintenance() -> tuple[int, int, int]:
    try:
        cleanup = cleanup_restore_staging()
        if cleanup["removed_terminal"] or cleanup["removed_orphan"]:
            logger.info(
                "Cleaned restore staging: terminal=%s orphan=%s preserved_staged=%s",
                cleanup["removed_terminal"],
                cleanup["removed_orphan"],
                cleanup["preserved_staged"],
            )
    except BackupRestoreWorkflowError as exc:
        # Staging cleanup is conservative housekeeping. A cleanup problem must
        # not prevent repository verification/retention from running.
        logger.warning("Could not clean restore staging safely: %s", exc)

    identity = load_node_identity()
    if identity is None:
        raise BackupMaintenanceError('Local Lattice node identity is unavailable')
    attempted = succeeded = failed = 0
    for job in eligible_jobs(identity.node_id):
        attempted += 1
        try:
            maintain_job(job['id'])
        except BackupMaintenanceError as exc:
            failed += 1
            logger.error(
                'Backup maintenance %s -> %s failed: %s',
                job['source_hostname'], job['target_name'], exc,
            )
        else:
            succeeded += 1
            logger.info(
                'Backup maintenance %s -> %s completed',
                job['source_hostname'], job['target_name'],
            )
    return attempted, succeeded, failed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [backup-maintenance] %(levelname)s %(message)s',
    )
    attempted, succeeded, failed = dispatch_maintenance()
    logger.info(
        'Backup maintenance complete: attempted=%s succeeded=%s failed=%s',
        attempted, succeeded, failed,
    )
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
