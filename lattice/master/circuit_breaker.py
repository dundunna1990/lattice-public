"""
Circuit breaker per (worker, action) to prevent repeated failures.
Tracks failures and opens after threshold; cooldown allows half-open probe.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from lattice.core.db import get_db_connection

logger = logging.getLogger(__name__)

# Default config (can be overridden via settings)
DEFAULT_THRESHOLD = 3           # failures before opening
DEFAULT_COOLDOWN_SECONDS = 30   # seconds before half-open


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

class CircuitBreaker:
    """Per-(worker, action) failure circuit breaker.

    States:
        closed   — normal; actions allowed.
        open     — failing; actions blocked until cooldown elapses.
        half_open — cooldown elapsed; exactly ONE probe action is allowed.
                    The first caller to atomically claim the half_open_token
                    gets to probe. Other callers see is_open() == True.

    Bulletproofness:
        - The half-open transition is atomic via SQL UPDATE.
        - The probe claim is atomic via SQL UPDATE (consumes the token).
        - If a probe caller dies without calling record_success/failure,
          a probe_started_at timestamp lets the next caller detect the
          stale probe and take over (after PROBE_TIMEOUT).
        - record_failure during half-open reopens the circuit immediately.
        - record_success during half-open closes the circuit.
    """

    def __init__(self, worker_id: int, action: str):
        self.worker_id = worker_id
        self.action = action

    @staticmethod
    def _new_token() -> str:
        import uuid
        return str(uuid.uuid4())

    def _get_row(self):
        """Fetch current state row. Returns None or sqlite3.Row."""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT state, failure_count, opened_at, half_open_at, half_open_token, probe_started_at "
                "FROM circuit_breaker_state WHERE worker_id = ? AND action = ?",
                (self.worker_id, self.action),
            )
            return cursor.fetchone()
        finally:
            conn.close()

    def _upsert_state(
        self,
        state: str,
        failure_count: int = 0,
        opened_at=None,
        half_open_at=None,
        half_open_token: str | None = None,
        probe_started_at: str | None = None,
    ) -> None:
        """Insert or update state. Half-open token is only set on transition."""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO circuit_breaker_state
                    (worker_id, action, state, failure_count, opened_at, half_open_at, half_open_token, probe_started_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker_id, action) DO UPDATE SET
                    state = excluded.state,
                    failure_count = excluded.failure_count,
                    opened_at = excluded.opened_at,
                    half_open_at = excluded.half_open_at,
                    half_open_token = COALESCE(excluded.half_open_token, circuit_breaker_state.half_open_token),
                    probe_started_at = excluded.probe_started_at
                """,
                (self.worker_id, self.action, state, failure_count,
                 opened_at, half_open_at, half_open_token, probe_started_at),
            )
            conn.commit()
        finally:
            conn.close()

    def _try_enter_half_open(self) -> bool:
        """If the circuit is open and cooldown has elapsed, transition to half_open
        and return True. Otherwise return False. Atomic via UPDATE.
        """
        row = self._get_row()
        if not row:
            return False
        state, _, opened_at, _, _, _ = row
        if state != "open" or not opened_at:
            return False
        opened_time = _parse_utc(opened_at)
        if _utc_now() - opened_time < timedelta(seconds=DEFAULT_COOLDOWN_SECONDS):
            return False
        # Cooldown elapsed — try to transition. The UPDATE with state=open
        # guard ensures only one caller wins the race.
        new_token = self._new_token()
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE circuit_breaker_state
                SET state = 'half_open',
                    half_open_at = ?,
                    half_open_token = ?,
                    failure_count = 0
                WHERE worker_id = ? AND action = ? AND state = 'open'
                """,
                (_utc_now().isoformat(), new_token, self.worker_id, self.action),
            )
            if cursor.rowcount == 1:
                conn.commit()
                logger.info(
                    f"Circuit breaker {self.worker_id}:{self.action} entered half-open (cooldown elapsed)"
                )
                return True
            return False
        finally:
            conn.close()

    def _try_claim_probe(self) -> bool:
        """If in half_open with a fresh token, atomically claim it.
        Returns True if this caller won the probe.
        """
        row = self._get_row()
        if not row:
            return False
        state, _, _, _, token, probe_started_at = row
        if state != "half_open":
            return False

        # A fresh token is an unclaimed probe. A NULL token with an old
        # probe_started_at is an abandoned claim whose owner died before
        # recording success/failure. Reclaim either case with ONE guarded
        # UPDATE so concurrent callers still produce exactly one winner.
        now = _utc_now()
        stale_before = (
            now - timedelta(seconds=DEFAULT_PROBE_TIMEOUT)
        ).isoformat()
        stale_claim = False
        if token is None and probe_started_at:
            try:
                stale_claim = (
                    _parse_utc(probe_started_at)
                    <= now - timedelta(seconds=DEFAULT_PROBE_TIMEOUT)
                )
            except (ValueError, TypeError):
                stale_claim = False

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE circuit_breaker_state
                SET half_open_token = NULL,
                    probe_started_at = ?
                WHERE worker_id = ? AND action = ? AND state = 'half_open'
                  AND (
                        half_open_token IS NOT NULL
                        OR (
                            half_open_token IS NULL
                            AND probe_started_at IS NOT NULL
                            AND probe_started_at <= ?
                        )
                  )
                """,
                (
                    now.isoformat(),
                    self.worker_id,
                    self.action,
                    stale_before,
                ),
            )
            conn.commit()
            won = cursor.rowcount == 1
            if won and stale_claim:
                logger.warning(
                    f"Circuit breaker {self.worker_id}:{self.action} probe timed out; taking over"
                )
            return won
        finally:
            conn.close()

    def record_failure(self) -> None:
        """Record a failure: increment count and possibly (re)open circuit."""
        row = self._get_row()
        if not row:
            self._upsert_state("closed", 1)
            return
        state, failure_count, opened_at, _, _, _ = row
        failure_count = failure_count or 0

        if state == "half_open":
            # Probe failed: reopen immediately
            self._upsert_state(
                "open",
                failure_count + 1,
                opened_at=_utc_now().isoformat(),
                half_open_at=None,
                half_open_token=None,
                probe_started_at=None,
            )
            logger.warning(
                f"Circuit breaker reopened for {self.worker_id}:{self.action} (probe failed)"
            )
            return

        if state == "open":
            # Already open: increment failure count, keep open
            failure_count += 1
            self._upsert_state("open", failure_count, opened_at=opened_at)
            return

        # closed state: increment, may transition to open
        failure_count += 1
        if failure_count >= DEFAULT_THRESHOLD:
            self._upsert_state(
                "open", failure_count, opened_at=_utc_now().isoformat()
            )
            logger.warning(
                f"Circuit breaker opened for {self.worker_id}:{self.action} "
                f"after {failure_count} failures"
            )
        else:
            self._upsert_state("closed", failure_count)

    def record_success(self) -> None:
        """Record a success: reset the circuit to closed."""
        self._upsert_state(
            "closed", 0, opened_at=None, half_open_at=None,
            half_open_token=None, probe_started_at=None,
        )
        logger.info(f"Circuit breaker reset for {self.worker_id}, action {self.action}")

    def is_open(self) -> bool:
        """Check if the circuit is currently blocking. Atomic via SQL.

        Returns:
            True  — action should be blocked (open, or half_open with
                    someone else holding the probe, or half_open with
                    a stale probe we just took over is a separate flow).
            False — action is allowed. Either state is closed, or the
                    caller just won the half-open probe claim.

        The caller MUST call record_success or record_failure after the
        action completes (especially if they won the half-open probe).
        """
        # Fast path: no breaker record exists
        row = self._get_row()
        if not row:
            return False
        state, _, opened_at, _, _, _ = row

        if state == "closed":
            return False

        if state == "open":
            if opened_at and _utc_now() - _parse_utc(opened_at) >= timedelta(
                seconds=DEFAULT_COOLDOWN_SECONDS
            ):
                # Cooldown elapsed — try to transition. If we win, we're
                # effectively the probe caller.
                if self._try_enter_half_open():
                    return self._try_claim_probe() is False
            return True

        if state == "half_open":
            # Try to claim the probe
            return not self._try_claim_probe()

        return False

    def reset(self) -> None:
        """Manually reset the circuit to closed."""
        self.record_success()


# Backward compatibility: keep the old module-level constants
DEFAULT_THRESHOLD = 3           # failures before opening
DEFAULT_COOLDOWN_SECONDS = 30   # seconds before half-open
DEFAULT_PROBE_TIMEOUT = 60      # seconds before a stuck probe is taken over
