import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from lattice.backup.restic import ResticError, ResticRepository


def _repo(tmp_path):
    password = tmp_path / 'password'
    password.write_text('x' * 64)
    password.chmod(0o600)
    repository = tmp_path / 'repo'
    repository.mkdir()
    repo = ResticRepository(repository, password, binary='/bin/true')
    return repo


def test_list_snapshot_directory_parses_shallow_json_lines(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    payload = '\n'.join([
        json.dumps({'struct_type': 'snapshot', 'id': 'a' * 64}),
        json.dumps({
            'struct_type': 'node', 'path': '/home/masteruser', 'name': 'masteruser',
            'type': 'dir', 'size': 0, 'mtime': '2026-09-03T01:00:00Z',
        }),
        json.dumps({
            'struct_type': 'node', 'path': '/home/masteruser/Documents', 'name': 'Documents',
            'type': 'dir', 'size': 0, 'mtime': '2026-09-03T01:00:00Z',
        }),
        json.dumps({
            'struct_type': 'node', 'path': '/home/masteruser/notes.txt', 'name': 'notes.txt',
            'type': 'file', 'size': 123, 'mtime': '2026-09-03T01:00:00Z',
        }),
    ])
    monkeypatch.setattr(
        repo, '_run', lambda args, timeout=0: SimpleNamespace(stdout=payload)
    )
    entries = repo.list_snapshot_directory('a' * 64, '/home/masteruser')
    assert [(item.name, item.entry_type, item.size) for item in entries] == [
        ('Documents', 'dir', 0), ('notes.txt', 'file', 123),
    ]


def test_list_snapshot_directory_rejects_recursive_surprise(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    payload = json.dumps({
        'struct_type': 'node',
        'path': '/home/masteruser/Documents/deep.txt',
        'name': 'deep.txt', 'type': 'file', 'size': 1,
    })
    monkeypatch.setattr(
        repo, '_run', lambda args, timeout=0: SimpleNamespace(stdout=payload)
    )
    with pytest.raises(ResticError, match='unexpectedly recursive'):
        repo.list_snapshot_directory('a' * 64, '/home/masteruser')


def test_list_snapshot_directory_rejects_parent_traversal(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(ResticError, match='unsafe'):
        repo.list_snapshot_directory('a' * 64, '/home/masteruser/../etc')


def test_snapshot_restore_stats_uses_restore_size_mode(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    seen = []
    payload = json.dumps({'total_size': 123456, 'total_file_count': 789})

    def fake_run(args, timeout=0):
        seen.append((args, timeout))
        return SimpleNamespace(stdout=payload)

    monkeypatch.setattr(repo, '_run', fake_run)
    stats = repo.snapshot_restore_stats('a' * 64)
    assert stats.total_size == 123456
    assert stats.total_file_count == 789
    assert seen == [(['stats', '--json', '--mode', 'restore-size', 'a' * 64], 300)]


def test_snapshot_restore_stats_rejects_invalid_shape(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setattr(
        repo, '_run', lambda args, timeout=0: SimpleNamespace(stdout=json.dumps({'total_size': -1}))
    )
    with pytest.raises(ResticError, match='incomplete'):
        repo.snapshot_restore_stats('a' * 64)


def test_dump_snapshot_file_returns_exact_bytes(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=b"abc123", stderr=b"")

    monkeypatch.setattr("lattice.backup.restic.subprocess.run", fake_run)
    payload = repo.dump_snapshot_file("a" * 64, "/home/masteruser/.bashrc")

    assert payload == b"abc123"
    assert "dump" in seen["command"]
    assert seen["command"][-3:] == ["dump", "a" * 64, "/home/masteruser/.bashrc"]
    assert seen["kwargs"]["capture_output"] is True


def test_dump_snapshot_file_rejects_unsafe_path(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(ResticError, match="path is invalid"):
        repo.dump_snapshot_file("a" * 64, "/home/masteruser/../etc/passwd")
