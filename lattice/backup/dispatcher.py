"""Local backup dispatcher invoked by the persistent systemd timer."""
from __future__ import annotations

import logging

from lattice.backup.runner import (
    BackupExecutionError,
    run_local_job,
    run_remote_job,
)
from lattice.backup.scheduler import due_jobs
from lattice.file_access.identity import load_node_identity

logger = logging.getLogger(__name__)


def dispatch_due_jobs() -> tuple[int, int, int]:
    """Run due jobs owned by this node; return attempted, succeeded, failed counts."""
    identity = load_node_identity()
    if identity is None:
        raise BackupExecutionError("Local Lattice node identity is unavailable")

    attempted = succeeded = failed = 0
    for job in due_jobs(source_node_id=identity.node_id):
        attempted += 1
        try:
            if job["host_node_id"] == identity.node_id:
                run_local_job(job["id"], local_node_id=identity.node_id)
            else:
                run_remote_job(job["id"], local_node_id=identity.node_id)
        except BackupExecutionError as exc:
            failed += 1
            logger.error(
                "Backup %s -> %s failed: %s",
                job["source_hostname"],
                job["target_name"],
                exc,
            )
        else:
            succeeded += 1
            logger.info(
                "Backup %s -> %s completed",
                job["source_hostname"],
                job["target_name"],
            )
    return attempted, succeeded, failed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [backup] %(levelname)s %(message)s",
    )
    attempted, succeeded, failed = dispatch_due_jobs()
    logger.info(
        "Backup dispatch complete: attempted=%s succeeded=%s failed=%s",
        attempted,
        succeeded,
        failed,
    )
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
