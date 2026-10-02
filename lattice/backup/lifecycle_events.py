"""Derive bounded Master-side lifecycle events from backup observation transitions."""
from __future__ import annotations


def backup_transition_events(
    previous: dict | None,
    current: dict,
    *,
    job_id: int,
    source_hostname: str,
    target_name: str,
) -> list[dict]:
    """Return only meaningful new events; initial state synchronization is silent."""
    if previous is None:
        return []
    events: list[dict] = []
    details = {
        "job_id": int(job_id),
        "source": str(source_hostname)[:100],
        "target": str(target_name)[:100],
    }
    old_state = previous.get("state")
    new_state = current.get("state")
    old_result = previous.get("last_result")
    new_result = current.get("last_result")
    old_failure_streak = int(previous.get("failure_streak") or 0)
    new_failure_streak = int(current.get("failure_streak") or 0)
    old_success = previous.get("last_success_at")
    new_success = current.get("last_success_at")

    if new_state == "running" and old_state != "running":
        events.append({
            "type": "backup.started",
            "severity": "info",
            "message": f"Backup started: {source_hostname} → {target_name}",
            "details": details,
        })

    if new_success and new_success != old_success:
        events.append({
            "type": "backup.completed",
            "severity": "ok",
            "message": f"Backup completed successfully: {source_hostname} → {target_name}",
            "details": {**details, "completed_at": str(new_success)[:80]},
        })
    elif new_result in {"failed", "interrupted"} and (
        new_result != old_result or new_failure_streak > old_failure_streak
    ):
        label = "interrupted" if new_result == "interrupted" else "failed"
        events.append({
            "type": f"backup.{label}",
            "severity": "warning",
            "message": f"Backup {label}: {source_hostname} → {target_name}",
            "details": {**details, "result": new_result},
        })
    return events
