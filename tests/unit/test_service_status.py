"""Regression tests for the shared Lattice service-status model."""

import pytest

from lattice.core.service_status import (
    FAILED_SERVICE_STATUSES,
    HEALTHY_SERVICE_STATUSES,
    WIRE_SERVICE_STATUSES,
    classify_service_status,
    is_service_failed,
    is_service_healthy,
)


def test_healthy_and_failure_sets_never_overlap():
    assert HEALTHY_SERVICE_STATUSES.isdisjoint(
        FAILED_SERVICE_STATUSES
    )


@pytest.mark.parametrize(
    "status",
    ["healthy", "active", "ok", "running"],
)
def test_all_healthy_statuses_classify_the_same(status):
    assert is_service_healthy(status) is True
    assert is_service_failed(status) is False
    assert classify_service_status(status) == "healthy"


@pytest.mark.parametrize(
    "status",
    ["unhealthy", "inactive", "failed", "down", "error"],
)
def test_all_failure_statuses_classify_the_same(status):
    assert is_service_failed(status) is True
    assert is_service_healthy(status) is False
    assert classify_service_status(status) == "failed"


def test_unknown_is_not_invented_as_success_or_failure():
    assert is_service_healthy("unknown") is False
    assert is_service_failed("unknown") is False
    assert classify_service_status("unknown") == "unknown"


def test_worker_wire_protocol_uses_canonical_statuses():
    assert WIRE_SERVICE_STATUSES == {
        "healthy",
        "unhealthy",
        "active",
        "inactive",
        "failed",
        "unknown",
    }


def test_normalization_is_case_and_whitespace_safe():
    assert is_service_healthy(" HEALTHY ")
    assert is_service_failed(" UnHeAlThY ")
