from lattice.backup.lifecycle_events import backup_transition_events


def _event(previous, current):
    return backup_transition_events(
        previous,
        current,
        job_id=7,
        source_hostname='worker-node',
        target_name='Backup Drive',
    )


def test_initial_observation_is_silent():
    assert _event(None, {
        'state': 'healthy', 'last_result': 'successful',
        'last_success_at': '2026-09-03T10:00:00+00:00', 'failure_streak': 0,
    }) == []


def test_running_transition_logs_started_once():
    events = _event(
        {'state': 'healthy', 'last_result': 'successful', 'last_success_at': 'old', 'failure_streak': 0},
        {'state': 'running', 'last_result': 'successful', 'last_success_at': 'old', 'failure_streak': 0},
    )
    assert [item['type'] for item in events] == ['backup.started']
    assert _event(
        {'state': 'running', 'last_result': 'successful', 'last_success_at': 'old', 'failure_streak': 0},
        {'state': 'running', 'last_result': 'successful', 'last_success_at': 'old', 'failure_streak': 0},
    ) == []


def test_new_success_logs_completed():
    events = _event(
        {'state': 'running', 'last_result': None, 'last_success_at': 'old', 'failure_streak': 0},
        {'state': 'healthy', 'last_result': 'successful', 'last_success_at': 'new', 'failure_streak': 0},
    )
    assert [item['type'] for item in events] == ['backup.completed']
    assert events[0]['severity'] == 'ok'


def test_repeated_failed_attempt_logs_when_failure_streak_increases():
    events = _event(
        {'state': 'pending', 'last_result': 'failed', 'last_success_at': 'old', 'failure_streak': 1},
        {'state': 'pending', 'last_result': 'failed', 'last_success_at': 'old', 'failure_streak': 2},
    )
    assert [item['type'] for item in events] == ['backup.failed']


def test_unchanged_failed_heartbeat_is_silent():
    assert _event(
        {'state': 'pending', 'last_result': 'failed', 'last_success_at': 'old', 'failure_streak': 2},
        {'state': 'pending', 'last_result': 'failed', 'last_success_at': 'old', 'failure_streak': 2},
    ) == []


def test_interrupted_attempt_is_distinct_event():
    events = _event(
        {'state': 'running', 'last_result': None, 'last_success_at': None, 'failure_streak': 0},
        {'state': 'pending', 'last_result': 'interrupted', 'last_success_at': None, 'failure_streak': 1},
    )
    assert [item['type'] for item in events] == ['backup.interrupted']
