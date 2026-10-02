"""
Canonical service-status vocabulary for Lattice.

All components that interpret worker service states should use this module
rather than defining their own lists.

The wire protocol intentionally accepts a smaller canonical vocabulary.
The UI also understands a few historical/compatibility aliases.
"""

from __future__ import annotations


# Statuses that mean a service is operating normally.
HEALTHY_SERVICE_STATUSES = frozenset({
    "healthy",
    "active",
    "ok",
    "running",
})

# Statuses that mean a service has a definite problem.
FAILED_SERVICE_STATUSES = frozenset({
    "unhealthy",
    "inactive",
    "failed",
    "down",
    "error",
})

# A service can also be unknown. Unknown is deliberately neither healthy nor
# failed in dashboard totals because Lattice does not have enough evidence.
UNKNOWN_SERVICE_STATUSES = frozenset({
    "unknown",
})

# Canonical statuses accepted from worker heartbeat messages.
# Compatibility/UI aliases such as "ok", "running", "down", and "error"
# are understood when displaying old data, but workers should send these.
WIRE_SERVICE_STATUSES = frozenset({
    "healthy",
    "unhealthy",
    "active",
    "inactive",
    "failed",
    "unknown",
})

ALL_SERVICE_STATUSES = (
    HEALTHY_SERVICE_STATUSES
    | FAILED_SERVICE_STATUSES
    | UNKNOWN_SERVICE_STATUSES
)

# Trusted static fragments used only by internal SQL queries. Keeping these
# here prevents the dashboard and CLI from silently developing different
# definitions again.
HEALTHY_SERVICE_STATUS_SQL = ", ".join(
    f"'{status}'"
    for status in sorted(HEALTHY_SERVICE_STATUSES)
)

FAILED_SERVICE_STATUS_SQL = ", ".join(
    f"'{status}'"
    for status in sorted(FAILED_SERVICE_STATUSES)
)


def normalize_service_status(status) -> str:
    if not isinstance(status, str):
        return "unknown"
    value = status.strip().lower()
    return value or "unknown"


def is_service_healthy(status) -> bool:
    return normalize_service_status(status) in HEALTHY_SERVICE_STATUSES


def is_service_failed(status) -> bool:
    return normalize_service_status(status) in FAILED_SERVICE_STATUSES


def classify_service_status(status) -> str:
    """
    Return one of: healthy, failed, unknown.
    """
    normalized = normalize_service_status(status)

    if normalized in HEALTHY_SERVICE_STATUSES:
        return "healthy"

    if normalized in FAILED_SERVICE_STATUSES:
        return "failed"

    return "unknown"
